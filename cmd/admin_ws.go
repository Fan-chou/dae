/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/control"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

const (
	wsMaxClients           = 16
	wsSendQueueSize        = 64
	wsWriteWait            = 5 * time.Second
	wsPongWait             = 60 * time.Second
	wsPingPeriod           = 25 * time.Second
	wsDefaultMetricsMs     = 1000
	wsDefaultConnectionsMs = 1000
	wsDefaultGroupsMs      = 5000
	wsMaxFrameBytes        = 16 << 10
)

var wsAuthTimeout = 3 * time.Second

type wsClientFrame struct {
	Type       string                        `json:"type"`
	Token      string                        `json:"token,omitempty"`
	ID         string                        `json:"id,omitempty"`
	Topic      string                        `json:"topic,omitempty"`
	IntervalMs int                           `json:"interval_ms,omitempty"`
	Filter     control.AdminConnectionFilter `json:"filter,omitempty"`
	Level      string                        `json:"level,omitempty"`
	Limit      int                           `json:"limit,omitempty"`
	Sort       string                        `json:"sort,omitempty"`
	Order      string                        `json:"order,omitempty"`
}

type wsServerFrame struct {
	Type  string `json:"type"`
	Topic string `json:"topic,omitempty"`
	TS    int64  `json:"ts,omitempty"`
	Seq   uint64 `json:"seq,omitempty"`
	Event string `json:"event,omitempty"`
	ID    string `json:"id,omitempty"`
	Data  any    `json:"data,omitempty"`
	Code  string `json:"code,omitempty"`
	Msg   string `json:"message,omitempty"`
	Ver   string `json:"version,omitempty"`
}

type wsTopicSub struct {
	interval time.Duration
	lastSent time.Time
	filter   control.AdminConnectionFilter
	minLevel logrus.Level
	limit    int
	sortBy   string
	order    string
}

type wsClient struct {
	hub       *adminWSHub
	conn      *websocket.Conn
	sendCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once

	subMu   sync.Mutex
	subs    map[string]*wsTopicSub
	dropped atomic.Uint64
}

func (c *wsClient) close() {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

func (c *wsClient) isClosed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *wsClient) enqueue(payload []byte) {
	if len(payload) == 0 {
		return
	}
	select {
	case <-c.done:
		return
	default:
	}
	select {
	case <-c.done:
	case c.sendCh <- payload:
	default:
		c.dropped.Add(1)
	}
}

func (c *wsClient) enqueueFrame(frame wsServerFrame) {
	b, err := json.Marshal(frame)
	if err != nil {
		return
	}
	c.enqueue(b)
}

type adminWSHub struct {
	server *adminServer

	observerMu    sync.Mutex
	mu            sync.Mutex
	closed        bool
	clients       map[*wsClient]struct{}
	pending       map[*wsClient]struct{}
	pendingSlots  int
	disconnectGen uint64
	topicSeq      map[string]uint64
	metricsCancel context.CancelFunc
	connsCancel   context.CancelFunc
	groupsCancel  context.CancelFunc
	logsCancel    func()
	logsDone      chan struct{}
	flowsActive   bool
	wg            sync.WaitGroup
}

func newAdminWSHub(server *adminServer) *adminWSHub {
	return &adminWSHub{
		server:   server,
		clients:  make(map[*wsClient]struct{}),
		pending:  make(map[*wsClient]struct{}),
		topicSeq: make(map[string]uint64),
	}
}

func (h *adminWSHub) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.closed = true
	h.disconnectGen++
	clients := make([]*wsClient, 0, len(h.clients)+len(h.pending))
	for c := range h.clients {
		clients = append(clients, c)
	}
	for c := range h.pending {
		clients = append(clients, c)
	}
	if h.metricsCancel != nil {
		h.metricsCancel()
		h.metricsCancel = nil
	}
	if h.connsCancel != nil {
		h.connsCancel()
		h.connsCancel = nil
	}
	if h.groupsCancel != nil {
		h.groupsCancel()
		h.groupsCancel = nil
	}
	if h.logsCancel != nil {
		h.logsCancel()
		h.logsCancel = nil
		h.logsDone = nil
	}
	h.flowsActive = false
	h.mu.Unlock()

	h.syncFlowObserver()
	for _, c := range clients {
		c.close()
	}
	h.wg.Wait()
}

// disconnectAll drops all active and pending WebSocket clients without shutting
// down the hub permanently (used on admin_secret or admin_listen hot reload).
func (h *adminWSHub) disconnectAll() {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.disconnectGen++
	clients := make([]*wsClient, 0, len(h.clients)+len(h.pending))
	for c := range h.clients {
		clients = append(clients, c)
		delete(h.clients, c)
	}
	for c := range h.pending {
		clients = append(clients, c)
	}
	if h.metricsCancel != nil {
		h.metricsCancel()
		h.metricsCancel = nil
	}
	if h.connsCancel != nil {
		h.connsCancel()
		h.connsCancel = nil
	}
	if h.groupsCancel != nil {
		h.groupsCancel()
		h.groupsCancel = nil
	}
	if h.logsCancel != nil {
		h.logsCancel()
		h.logsCancel = nil
		h.logsDone = nil
	}
	flowsWereActive := h.flowsActive
	h.flowsActive = false
	h.mu.Unlock()

	if flowsWereActive {
		h.syncFlowObserver()
	}
	for _, c := range clients {
		c.close()
	}
}

func (h *adminWSHub) ActiveClients() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

func (h *adminWSHub) ActiveTopics() map[string]int {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	counts := make(map[string]int)
	for c := range h.clients {
		c.subMu.Lock()
		for topic := range c.subs {
			counts[topic]++
		}
		c.subMu.Unlock()
	}
	return counts
}

func (h *adminWSHub) hasTopicSubscribersLocked(topic string) bool {
	for c := range h.clients {
		c.subMu.Lock()
		_, ok := c.subs[topic]
		c.subMu.Unlock()
		if ok {
			return true
		}
	}
	return false
}

func (h *adminWSHub) handleWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if !h.server.isOriginAllowedForRequest(origin, r) {
			writeAdminAPIError(w, http.StatusForbidden, "origin_forbidden", "origin not allowed")
			return
		}
	}

	clientIP := clientIPFromRequest(r)
	if h.server != nil && h.server.authLimiter != nil {
		if allowed, retryAfter := h.server.authLimiter.allow(clientIP); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			writeAdminAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many authentication failures")
			return
		}
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		writeAdminAPIError(w, http.StatusServiceUnavailable, "shutting_down", "server is shutting down")
		return
	}
	if len(h.clients)+h.pendingSlots >= wsMaxClients {
		h.mu.Unlock()
		writeAdminAPIError(w, http.StatusServiceUnavailable, "too_many_clients", "maximum WebSocket clients reached")
		return
	}
	h.pendingSlots++
	gen := h.disconnectGen
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()

	slotHeld := true
	var pendingClient *wsClient
	releasePending := func() {
		if !slotHeld {
			return
		}
		slotHeld = false
		h.mu.Lock()
		if pendingClient != nil {
			delete(h.pending, pendingClient)
		}
		if h.pendingSlots > 0 {
			h.pendingSlots--
		}
		h.mu.Unlock()
	}
	defer releasePending()

	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 8192,
		CheckOrigin: func(req *http.Request) bool {
			origin := strings.TrimSpace(req.Header.Get("Origin"))
			if origin == "" {
				return true
			}
			return h.server.isOriginAllowedForRequest(origin, req)
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &wsClient{
		hub:    h,
		conn:   conn,
		sendCh: make(chan []byte, wsSendQueueSize),
		done:   make(chan struct{}),
		subs:   make(map[string]*wsTopicSub),
	}

	h.mu.Lock()
	if h.closed || h.disconnectGen != gen {
		h.mu.Unlock()
		client.close()
		return
	}
	pendingClient = client
	h.pending[client] = struct{}{}
	h.mu.Unlock()

	if !h.authenticateClient(client, r) {
		client.close()
		return
	}

	h.mu.Lock()
	delete(h.pending, client)
	pendingClient = nil
	if h.pendingSlots > 0 {
		h.pendingSlots--
	}
	slotHeld = false
	if h.closed || h.disconnectGen != gen || len(h.clients) >= wsMaxClients {
		h.mu.Unlock()
		client.close()
		return
	}
	h.clients[client] = struct{}{}
	h.wg.Add(2)
	h.mu.Unlock()

	go func() {
		defer h.wg.Done()
		client.writePump()
	}()
	go func() {
		defer h.wg.Done()
		defer h.removeClient(client)
		client.readPump()
	}()
}

func (h *adminWSHub) authenticateClient(client *wsClient, r *http.Request) bool {
	clientIP := clientIPFromRequest(r)
	if h.server != nil && h.server.authLimiter != nil {
		if allowed, retryAfter := h.server.authLimiter.allow(clientIP); !allowed {
			_ = client.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			_ = client.conn.WriteJSON(wsServerFrame{
				Type: "auth_error",
				Code: "rate_limited",
				Msg:  "too many authentication failures; retry after " + strconv.Itoa(retryAfter) + "s",
			})
			_ = client.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4001, "rate limited"), time.Now().Add(wsWriteWait))
			return false
		}
	}

	client.conn.SetReadLimit(wsMaxFrameBytes)
	_ = client.conn.SetReadDeadline(time.Now().Add(wsAuthTimeout))
	var frame wsClientFrame
	if err := client.conn.ReadJSON(&frame); err != nil {
		if client.isClosed() {
			return false
		}
		if h.server != nil && h.server.authLimiter != nil {
			h.server.authLimiter.recordFailure(clientIP)
		}
		var netErr net.Error
		code := "invalid_auth_frame"
		msg := "invalid authentication frame"
		if errors.As(err, &netErr) && netErr.Timeout() {
			code = "auth_timeout"
			msg = "authentication timeout"
		}
		_ = client.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		_ = client.conn.WriteJSON(wsServerFrame{
			Type: "auth_error",
			Code: code,
			Msg:  msg,
		})
		_ = client.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4001, msg), time.Now().Add(wsWriteWait))
		return false
	}
	if frame.Type != "auth" || !adminSecretMatches(frame.Token, h.server.currentSecret()) {
		if h.server != nil && h.server.authLimiter != nil {
			h.server.authLimiter.recordFailure(clientIP)
		}
		_ = client.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		_ = client.conn.WriteJSON(wsServerFrame{
			Type: "auth_error",
			Code: "unauthorized",
			Msg:  "invalid authentication token",
		})
		_ = client.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4001, "unauthorized"), time.Now().Add(wsWriteWait))
		return false
	}
	if h.server != nil && h.server.authLimiter != nil {
		h.server.authLimiter.recordSuccess(clientIP)
	}
	_ = client.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	if err := client.conn.WriteJSON(wsServerFrame{
		Type: "auth_ok",
		Ver:  "v1",
	}); err != nil {
		return false
	}
	return true
}

func (h *adminWSHub) removeClient(client *wsClient) {
	client.close()
	h.mu.Lock()
	_, existed := h.clients[client]
	if existed {
		delete(h.clients, client)
	}
	h.mu.Unlock()
	if existed {
		h.reconcileSubscribers()
	}
}

func (c *wsClient) writePump() {
	ticker := time.NewTicker(wsPingPeriod)
	defer func() {
		ticker.Stop()
		c.close()
	}()
	for {
		select {
		case <-c.done:
			return
		case payload := <-c.sendCh:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *wsClient) readPump() {
	_ = c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})
	for {
		var frame wsClientFrame
		if err := c.conn.ReadJSON(&frame); err != nil {
			var closeErr *websocket.CloseError
			_ = errors.As(err, &closeErr)
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
		switch frame.Type {
		case "ping":
			c.enqueueFrame(wsServerFrame{
				Type: "pong",
				ID:   frame.ID,
				TS:   time.Now().UnixMilli(),
			})
		case "sub":
			c.handleSub(frame)
		case "unsub":
			c.handleUnsub(frame.Topic)
		default:
			c.enqueueFrame(wsServerFrame{
				Type: "error",
				Code: "unsupported_frame",
				Msg:  "unsupported frame type",
			})
		}
	}
}

func clampWSInterval(ms, defMs, minMs, maxMs int) time.Duration {
	if ms <= 0 {
		ms = defMs
	}
	if ms < minMs {
		ms = minMs
	}
	if ms > maxMs {
		ms = maxMs
	}
	return time.Duration(ms) * time.Millisecond
}

func (c *wsClient) handleSub(frame wsClientFrame) {
	topic := strings.TrimSpace(frame.Topic)
	var sub *wsTopicSub
	switch topic {
	case "metrics":
		sub = &wsTopicSub{interval: clampWSInterval(frame.IntervalMs, wsDefaultMetricsMs, 500, 10000)}
	case "connections":
		limit := frame.Limit
		if limit <= 0 || limit > 1024 {
			limit = 256
		}
		sub = &wsTopicSub{
			interval: clampWSInterval(frame.IntervalMs, wsDefaultConnectionsMs, 500, 10000),
			filter:   frame.Filter,
			limit:    limit,
			sortBy:   frame.Sort,
			order:    frame.Order,
		}
	case "groups":
		sub = &wsTopicSub{interval: clampWSInterval(frame.IntervalMs, wsDefaultGroupsMs, 1000, 30000)}
	case "logs":
		minLvl := logrus.TraceLevel
		if frame.Level != "" {
			parsed, err := logrus.ParseLevel(strings.TrimSpace(frame.Level))
			if err != nil {
				c.enqueueFrame(wsServerFrame{Type: "error", Code: "invalid_level", Msg: "invalid log level"})
				return
			}
			minLvl = parsed
		}
		sub = &wsTopicSub{minLevel: minLvl}
	case "flows":
		sub = &wsTopicSub{filter: frame.Filter}
	case "events":
		sub = &wsTopicSub{}
	default:
		c.enqueueFrame(wsServerFrame{Type: "error", Code: "invalid_topic", Msg: "unknown subscription topic"})
		return
	}

	c.subMu.Lock()
	c.subs[topic] = sub
	c.subMu.Unlock()

	c.hub.reconcileSubscribers()
	c.hub.sendInitialSnapshot(c, topic, sub)
}

func (c *wsClient) handleUnsub(topic string) {
	topic = strings.TrimSpace(topic)
	c.subMu.Lock()
	delete(c.subs, topic)
	c.subMu.Unlock()
	c.hub.reconcileSubscribers()
}

func (h *adminWSHub) sendInitialSnapshot(client *wsClient, topic string, sub *wsTopicSub) {
	now := time.Now()
	switch topic {
	case "metrics":
		data := h.server.buildMetricsBody()
		client.subMu.Lock()
		sub.lastSent = now
		client.subMu.Unlock()
		client.enqueueFrame(wsServerFrame{Type: "data", Topic: "metrics", TS: now.UnixMilli(), Seq: h.nextTopicSeq("metrics"), Data: data})
	case "connections":
		data := h.server.snapshotTrackedConnections(sub.limit, sub.filter, sub.sortBy, sub.order)
		client.subMu.Lock()
		sub.lastSent = now
		client.subMu.Unlock()
		client.enqueueFrame(wsServerFrame{Type: "data", Topic: "connections", TS: now.UnixMilli(), Seq: h.nextTopicSeq("connections"), Data: data})
	case "groups":
		if data, ok := h.server.buildGroupsBody(); ok {
			client.subMu.Lock()
			sub.lastSent = now
			client.subMu.Unlock()
			client.enqueueFrame(wsServerFrame{Type: "data", Topic: "groups", TS: now.UnixMilli(), Seq: h.nextTopicSeq("groups"), Data: data})
		}
	}
}

func (h *adminWSHub) nextTopicSeq(topic string) uint64 {
	h.mu.Lock()
	h.topicSeq[topic]++
	seq := h.topicSeq[topic]
	h.mu.Unlock()
	return seq
}

func (h *adminWSHub) reconcileSubscribers() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	wantMetrics := h.hasTopicSubscribersLocked("metrics")
	wantConns := h.hasTopicSubscribersLocked("connections")
	wantGroups := h.hasTopicSubscribersLocked("groups")
	wantLogs := h.hasTopicSubscribersLocked("logs")
	wantFlows := h.hasTopicSubscribersLocked("flows")

	if wantMetrics && h.metricsCancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		h.metricsCancel = cancel
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.runSampler(ctx, "metrics", 500*time.Millisecond)
		}()
	} else if !wantMetrics && h.metricsCancel != nil {
		h.metricsCancel()
		h.metricsCancel = nil
	}

	if wantConns && h.connsCancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		h.connsCancel = cancel
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.runSampler(ctx, "connections", 500*time.Millisecond)
		}()
	} else if !wantConns && h.connsCancel != nil {
		h.connsCancel()
		h.connsCancel = nil
	}

	if wantGroups && h.groupsCancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		h.groupsCancel = cancel
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.runSampler(ctx, "groups", 1000*time.Millisecond)
		}()
	} else if !wantGroups && h.groupsCancel != nil {
		h.groupsCancel()
		h.groupsCancel = nil
	}

	if wantLogs && h.logsCancel == nil && h.server != nil && h.server.logRing != nil {
		ch, cancel := h.server.logRing.Subscribe(logrus.TraceLevel)
		done := make(chan struct{})
		h.logsCancel = func() {
			cancel()
			close(done)
		}
		h.logsDone = done
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.runLogPump(ch, done)
		}()
	} else if !wantLogs && h.logsCancel != nil {
		h.logsCancel()
		h.logsCancel = nil
		h.logsDone = nil
	}

	flowsChanged := wantFlows != h.flowsActive
	h.flowsActive = wantFlows
	h.mu.Unlock()

	if flowsChanged {
		h.syncFlowObserver()
	}
}

func (h *adminWSHub) syncFlowObserver() {
	if h == nil || h.server == nil {
		return
	}
	h.observerMu.Lock()
	defer h.observerMu.Unlock()

	plane := h.server.currentPlane()
	if plane == nil {
		return
	}
	h.mu.Lock()
	active := h.flowsActive && !h.closed
	h.mu.Unlock()
	if active {
		plane.SetClosedFlowObserver(h.onClosedFlow)
	} else {
		plane.SetClosedFlowObserver(nil)
	}
}

func (h *adminWSHub) runSampler(ctx context.Context, topic string, tickInterval time.Duration) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.sampleAndDispatch(topic, now)
		}
	}
}

func (h *adminWSHub) sampleAndDispatch(topic string, now time.Time) {
	type target struct {
		client *wsClient
		sub    *wsTopicSub
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	var due []target
	for c := range h.clients {
		c.subMu.Lock()
		sub := c.subs[topic]
		if sub != nil && (sub.lastSent.IsZero() || now.Sub(sub.lastSent) >= sub.interval) {
			sub.lastSent = now
			due = append(due, target{client: c, sub: sub})
		}
		c.subMu.Unlock()
	}
	h.mu.Unlock()

	if len(due) == 0 {
		return
	}

	seq := h.nextTopicSeq(topic)
	ts := now.UnixMilli()

	switch topic {
	case "metrics":
		payload, err := json.Marshal(wsServerFrame{
			Type:  "data",
			Topic: "metrics",
			TS:    ts,
			Seq:   seq,
			Data:  h.server.buildMetricsBody(),
		})
		if err != nil {
			return
		}
		for _, item := range due {
			item.client.enqueue(payload)
		}
	case "groups":
		body, ok := h.server.buildGroupsBody()
		if !ok {
			return
		}
		payload, err := json.Marshal(wsServerFrame{
			Type:  "data",
			Topic: "groups",
			TS:    ts,
			Seq:   seq,
			Data:  body,
		})
		if err != nil {
			return
		}
		for _, item := range due {
			item.client.enqueue(payload)
		}
	case "connections":
		for _, item := range due {
			snap := h.server.snapshotTrackedConnections(item.sub.limit, item.sub.filter, item.sub.sortBy, item.sub.order)
			item.client.enqueueFrame(wsServerFrame{
				Type:  "data",
				Topic: "connections",
				TS:    ts,
				Seq:   seq,
				Data:  snap,
			})
		}
	}
}

func (h *adminWSHub) runLogPump(ch <-chan AdminLogEntry, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			lvl, parseErr := logrus.ParseLevel(entry.Level)
			h.mu.Lock()
			if h.closed {
				h.mu.Unlock()
				return
			}
			clients := make([]*wsClient, 0, len(h.clients))
			for c := range h.clients {
				c.subMu.Lock()
				sub := c.subs["logs"]
				match := sub != nil && (parseErr != nil || lvl <= sub.minLevel)
				c.subMu.Unlock()
				if match {
					clients = append(clients, c)
				}
			}
			h.mu.Unlock()
			if len(clients) == 0 {
				continue
			}
			payload, err := json.Marshal(wsServerFrame{
				Type:  "data",
				Topic: "logs",
				TS:    time.Now().UnixMilli(),
				Seq:   entry.Seq,
				Data:  entry,
			})
			if err != nil {
				continue
			}
			for _, c := range clients {
				c.enqueue(payload)
			}
		}
	}
}

func (h *adminWSHub) onClosedFlow(flow control.AdminClosedFlow) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	type subPair struct {
		client *wsClient
		filter control.AdminConnectionFilter
	}
	var recipients []subPair
	for c := range h.clients {
		c.subMu.Lock()
		sub := c.subs["flows"]
		if sub != nil {
			recipients = append(recipients, subPair{client: c, filter: sub.filter})
		}
		c.subMu.Unlock()
	}
	h.mu.Unlock()

	for _, rec := range recipients {
		if !rec.filter.IsEmpty() && !flow.Matches(rec.filter) {
			continue
		}
		rec.client.enqueueFrame(wsServerFrame{
			Type:  "data",
			Topic: "flows",
			TS:    time.Now().UnixMilli(),
			Seq:   flow.Seq,
			Data:  flow,
		})
	}
}

func (h *adminWSHub) emitEvent(event string, data any) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.closed || len(h.clients) == 0 {
		h.mu.Unlock()
		return
	}
	var targets []*wsClient
	for c := range h.clients {
		c.subMu.Lock()
		_, ok := c.subs["events"]
		c.subMu.Unlock()
		if ok {
			targets = append(targets, c)
		}
	}
	h.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	payload, err := json.Marshal(wsServerFrame{
		Type:  "event",
		Topic: "events",
		TS:    time.Now().UnixMilli(),
		Seq:   h.nextTopicSeq("events"),
		Event: event,
		Data:  data,
	})
	if err != nil {
		return
	}
	for _, c := range targets {
		c.enqueue(payload)
	}
}

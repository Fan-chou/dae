/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/component/observation"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

const (
	adminReadTimeout           = 10 * time.Second
	adminWriteTimeout          = 30 * time.Second
	adminSourcesRefreshTimeout = 3 * time.Minute
	adminShutdownTimeout       = 2 * time.Second
	adminMaxBodyBytes          = 1 << 14
	adminProbeCooldown         = 3 * time.Second
)

type adminPlane interface {
	AdminSystemInfo(version string) control.AdminSystemInfo
	AdminMetricsSnapshot() control.AdminMetricsSnapshot
	AdminMetricsHistory(windowSec, maxPoints int) []control.AdminTrafficSample
	AdminQuality(group, host string) []map[string]any
	AdminGroups() []control.AdminGroup
	SetGroupSelection(groupName, memberName string) error
	TriggerLatencyChecksForGroup(groupName string) error
	AdminConnections(limit int, filter control.AdminConnectionFilter) control.AdminConnectionsSnapshot
	AdminClosedFlows(limit int, filter control.AdminConnectionFilter) control.AdminClosedFlowsSnapshot
	AdminTrafficSummary(topN int) control.AdminTrafficSummary
	AdminResetTrafficSummary()
	AdminCloseConnection(id string) bool
	AdminCloseConnections(filter control.AdminConnectionFilter) int
	AdminKernelConnections(limit int, src, mac string, resolveDomains bool) control.AdminKernelConnectionsSnapshot
	AdminCloseKernelConnection(req control.AdminKernelCloseRequest) (control.AdminKernelCloseResult, error)
	SetClosedFlowObserver(fn func(control.AdminClosedFlow))
}

type adminPlaneProvider func() adminPlane

type adminReloadFunc func() bool

type adminSourcesRefreshResult struct {
	Changed      bool   `json:"changed"`
	UsedLastGood bool   `json:"used_last_good,omitempty"`
	ReloadQueued bool   `json:"reload_queued,omitempty"`
	Warning      string `json:"warning,omitempty"`
}

type adminSourcesRefresher func(context.Context) (adminSourcesRefreshResult, error)

type adminServer struct {
	mu          sync.Mutex
	http        *http.Server
	listen      string
	boundAddr   string
	secret      string
	corsOrigins map[string]struct{}
	rawCorsList []string
	logFile     string
	configDir   string
	log         *logrus.Logger
	plane       adminPlaneProvider
	reload      adminReloadFunc
	inbounds    func() []control.InboundStatus

	reloadManager        *reloadManager
	resolveListenFn      func(context.Context, string) (string, error)
	activeSnapshot       *adminConfigSnapshot
	pendingAdminDigest   string
	lastReloadError      string
	lastReloadRolledBack bool
	suspended            bool

	authLimiter *adminAuthLimiter
	logRing     *adminLogRing
	connTracker *adminConnectionTracker
	wsHub       *adminWSHub

	probeMu       sync.Mutex
	lastProbeByGp map[string]time.Time

	sourcesMu        sync.Mutex
	sourcesRefreshing atomic.Bool
	sourcesRefresher adminSourcesRefresher
}

type adminAPIErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type adminAPIErrorBody struct {
	Error adminAPIErrorDetail `json:"error"`
}

type adminSystemBody struct {
	control.AdminSystemInfo
	Generation           string `json:"generation,omitempty"`
	SyncWarning          string `json:"sync_warning,omitempty"`
	ConfigInSync         bool   `json:"config_in_sync"`
	LastReloadError      string `json:"last_reload_error,omitempty"`
	ReloadPending        bool   `json:"reload_pending,omitempty"`
	LastReloadRolledBack bool   `json:"last_reload_rolled_back,omitempty"`
}

type adminGroupPutBody struct {
	Member string `json:"member"`
}

type adminLogLevelPutBody struct {
	Level string `json:"level"`
}

type adminLogsResponseBody struct {
	Entries   []AdminLogEntry `json:"entries"`
	LatestSeq uint64          `json:"latest_seq"`
}

type adminSourcesBody struct {
	Mihomo        MihomoStatus       `json:"mihomo"`
	Geodata       GeodataStatus      `json:"geodata"`
	RuleProviders RuleProviderStatus `json:"rule_providers"`
	SyncWarning   string             `json:"sync_warning,omitempty"`
}

type adminReloadBody struct {
	Queued bool `json:"queued"`
}

func newAdminServer(log *logrus.Logger, logFile, configDir string, plane adminPlaneProvider, reload adminReloadFunc) *adminServer {
	s := &adminServer{
		logFile:       logFile,
		configDir:     configDir,
		log:           log,
		plane:         plane,
		reload:        reload,
		authLimiter:   newAdminAuthLimiter(),
		logRing:       newAdminLogRing(),
		connTracker:   newAdminConnectionTracker(),
		lastProbeByGp: make(map[string]time.Time),
	}
	s.wsHub = newAdminWSHub(s)
	return s
}

func (s *adminServer) setLogRing(ring *adminLogRing) {
	if s == nil || ring == nil {
		return
	}
	s.mu.Lock()
	s.logRing = ring
	s.mu.Unlock()
}

func (s *adminServer) setSourcesRefresher(fn adminSourcesRefresher) {
	if s == nil {
		return
	}
	s.sourcesMu.Lock()
	s.sourcesRefresher = fn
	s.sourcesMu.Unlock()
}

func (s *adminServer) setInbounds(provider func() []control.InboundStatus) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.inbounds = provider
	s.mu.Unlock()
}

func (s *adminServer) setReloadManager(m *reloadManager) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.reloadManager = m
	s.mu.Unlock()
}

func (s *adminServer) currentInbounds() func() []control.InboundStatus {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inbounds
}

func (s *adminServer) currentSecret() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secret
}

func (s *adminServer) emitWSEvent(event string, data any) {
	if s != nil && s.wsHub != nil {
		s.wsHub.emitEvent(event, data)
	}
}

func (s *adminServer) captureActiveSnapshot(snap *adminConfigSnapshot) {
	if s == nil {
		return
	}
	adminConfigWriteMu.Lock()
	defer adminConfigWriteMu.Unlock()

	s.mu.Lock()
	configDir := s.configDir
	s.mu.Unlock()

	if snap != nil {
		writeAdminLastGoodSnapshot(configDir, *snap)
	}
	s.mu.Lock()
	s.activeSnapshot = snap
	s.mu.Unlock()
}

func (s *adminServer) recordPendingAdminWriteLocked() {
	if s == nil {
		return
	}
	s.mu.Lock()
	configDir := s.configDir
	hasActive := s.activeSnapshot != nil
	s.mu.Unlock()

	var digest string
	if hasActive {
		if snap, err := readAdminConfigSnapshot(configDir); err == nil {
			digest = snap.digest
		}
	}
	s.mu.Lock()
	s.pendingAdminDigest = digest
	s.lastReloadError = ""
	s.lastReloadRolledBack = false
	s.mu.Unlock()
}

func (s *adminServer) markReloadStarted() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.lastReloadError = ""
	s.lastReloadRolledBack = false
	s.mu.Unlock()
	s.emitWSEvent("reload_started", nil)
}

func (s *adminServer) markReloadSucceeded(snap *adminConfigSnapshot) {
	if s == nil {
		return
	}
	adminConfigWriteMu.Lock()
	defer adminConfigWriteMu.Unlock()

	s.mu.Lock()
	configDir := s.configDir
	s.suspended = false
	s.lastReloadError = ""
	s.lastReloadRolledBack = false
	s.pendingAdminDigest = ""
	s.mu.Unlock()

	if snap != nil {
		writeAdminLastGoodSnapshot(configDir, *snap)
	}
	s.mu.Lock()
	s.activeSnapshot = snap
	s.mu.Unlock()
	invalidateAdminFileCaches()
	if s.connTracker != nil {
		s.connTracker.Invalidate()
	}
	if s.wsHub != nil {
		s.wsHub.syncFlowObserver()
	}
	s.emitWSEvent("reload_succeeded", nil)
}

func (s *adminServer) markSuspended() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.suspended = true
	s.mu.Unlock()
}

func (s *adminServer) handleAsyncReloadFailure(errMsg string) {
	if s == nil {
		return
	}
	adminConfigWriteMu.Lock()
	defer adminConfigWriteMu.Unlock()

	sanitized := ""
	if strings.TrimSpace(errMsg) != "" {
		sanitized = sanitizeAdminError(errors.New(errMsg))
	}

	s.mu.Lock()
	configDir := s.configDir
	pendingDigest := s.pendingAdminDigest
	activeSnap := s.activeSnapshot
	s.lastReloadError = sanitized
	s.pendingAdminDigest = ""
	s.lastReloadRolledBack = false
	s.mu.Unlock()

	rolledBack := false
	if pendingDigest != "" && activeSnap != nil {
		curSnap, err := readAdminConfigSnapshot(configDir)
		if err == nil && curSnap.digest == pendingDigest {
			if rErr := restoreAdminConfigSnapshot(configDir, *activeSnap); rErr != nil {
				s.warnf("admin config reload failed (%s) and rollback failed: %v", sanitized, rErr)
			} else {
				invalidateAdminFileCaches()
				s.mu.Lock()
				s.lastReloadRolledBack = true
				s.mu.Unlock()
				rolledBack = true
				s.warnf("admin config reload failed (%s); restored last good configuration", sanitized)
			}
		}
	}
	s.emitWSEvent("reload_failed", map[string]any{
		"error":       sanitized,
		"rolled_back": rolledBack,
	})
}

type adminReloadStatusSnapshot struct {
	configInSync         bool
	lastReloadError      string
	reloadPending        bool
	lastReloadRolledBack bool
}

func (s *adminServer) reloadStatusSnapshot() adminReloadStatusSnapshot {
	adminConfigWriteMu.Lock()
	defer adminConfigWriteMu.Unlock()

	s.mu.Lock()
	rm := s.reloadManager
	activeSnap := s.activeSnapshot
	lastErr := s.lastReloadError
	rolledBack := s.lastReloadRolledBack
	suspended := s.suspended
	configDir := s.configDir
	s.mu.Unlock()

	var reloadActive, reloading, reloadPending bool
	if rm != nil {
		reloadActive = rm.reloadActive.Load()
		reloading = rm.reloading.Load()
		reloadPending = rm.reloadPending.Load() || reloadActive || reloading
		if err := rm.reloadError(); err != nil {
			lastErr = sanitizeAdminError(err)
		}
	}

	inSync := activeSnap != nil && !suspended && !reloadActive && !reloading
	if inSync {
		curSnap, err := readAdminConfigSnapshot(configDir)
		if err != nil || curSnap.digest != activeSnap.digest {
			inSync = false
		}
	}
	if lastErr != "" && !rolledBack {
		inSync = false
	}

	return adminReloadStatusSnapshot{
		configInSync:         inSync,
		lastReloadError:      lastErr,
		reloadPending:        reloadPending,
		lastReloadRolledBack: rolledBack,
	}
}

func buildCorsOriginSet(origins []string) map[string]struct{} {
	if len(origins) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(origins))
	for _, raw := range origins {
		canon, err := config.CanonicalizeAdminOrigin(raw)
		if err == nil && canon != "" {
			set[canon] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func (s *adminServer) isOriginAllowed(origin string) bool {
	if s == nil {
		return false
	}
	canon, err := config.CanonicalizeAdminOrigin(origin)
	if err != nil {
		return false
	}
	s.mu.Lock()
	_, ok := s.corsOrigins[canon]
	s.mu.Unlock()
	return ok
}

func (s *adminServer) refresh(listen, secret string) {
	s.refreshWithCORS(listen, secret, nil)
}

func (s *adminServer) refreshWithCORS(listen, secret string, corsOrigins []string) {
	if s == nil {
		return
	}
	listen = strings.TrimSpace(listen)
	secret = strings.TrimSpace(secret)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.corsOrigins = buildCorsOriginSet(corsOrigins)
	s.rawCorsList = append([]string(nil), corsOrigins...)

	if listen == s.listen && secret == s.secret && (s.http != nil || listen == "") {
		return
	}
	s.stopLocked()
	if s.wsHub != nil {
		s.wsHub.disconnectAll()
	}
	s.listen = listen
	s.secret = secret
	if listen == "" {
		return
	}
	resolveFn := s.resolveListenFn
	if resolveFn == nil {
		resolveFn = config.ResolveAndValidateAdminListen
	}
	resolvedListen, err := resolveFn(context.Background(), listen)
	if err != nil {
		s.warnf("admin HTTP disabled: %v", err)
		return
	}
	if secret == "" {
		s.warnf("admin HTTP disabled: admin_secret is empty")
		return
	}
	ln, err := net.Listen("tcp", resolvedListen)
	if err != nil {
		s.warnf("admin HTTP listen failed (tproxy continues): %v", err)
		return
	}
	mux := s.buildMux()
	boundAddr := ln.Addr().String()
	server := &http.Server{
		Addr:         boundAddr,
		Handler:      s.withSecurityHeaders(s.withAdminCORS(mux)),
		ReadTimeout:  adminReadTimeout,
		WriteTimeout: adminWriteTimeout,
	}
	s.http = server
	s.boundAddr = boundAddr
	go func() {
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.warnf("admin HTTP listen failed (tproxy continues): %v", err)
		}
	}()
	s.infof("admin HTTP listening on %s", boundAddr)
}

func (s *adminServer) buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/system", s.withAdminAuth(s.handleSystem))
	mux.HandleFunc("/api/v1/system/log-level", s.withAdminAuth(s.handleSystemLogLevel))
	mux.HandleFunc("/api/v1/system/reload", s.withAdminAuth(s.handleReload))
	mux.HandleFunc("/api/v1/metrics", s.withAdminAuth(s.handleMetrics))
	mux.HandleFunc("/api/v1/metrics/history", s.withAdminAuth(s.handleMetricsHistory))
	mux.HandleFunc("/api/v1/groups", s.withAdminAuth(s.handleGroups))
	mux.HandleFunc("/api/v1/groups/", s.withAdminAuth(s.handleGroup))
	mux.HandleFunc("/api/v1/connections", s.withAdminAuth(s.handleConnections))
	mux.HandleFunc("/api/v1/connections/close", s.withAdminAuth(s.handleConnectionsClose))
	mux.HandleFunc("/api/v1/connections/kernel", s.withAdminAuth(s.handleKernelConnections))
	mux.HandleFunc("/api/v1/connections/", s.withAdminAuth(s.handleConnectionByID))
	mux.HandleFunc("/api/v1/flows/closed", s.withAdminAuth(s.handleClosedFlows))
	mux.HandleFunc("/api/v1/traffic/summary", s.withAdminAuth(s.handleTrafficSummary))
	mux.HandleFunc("/api/v1/traffic/reset", s.withAdminAuth(s.handleTrafficReset))
	mux.HandleFunc("/api/v1/inbounds", s.withAdminAuth(s.handleInbounds))
	mux.HandleFunc("/api/v1/config", s.withAdminAuth(s.handleConfig))
	mux.HandleFunc("/api/v1/config/effective", s.withAdminAuth(s.handleEffectiveConfig))
	mux.HandleFunc("/api/v1/sources", s.withAdminAuth(s.handleSources))
	mux.HandleFunc("/api/v1/sources/refresh", s.withAdminAuth(s.handleSourcesRefresh))
	mux.HandleFunc("/api/v1/logs", s.withAdminAuth(s.handleLogs))
	mux.HandleFunc("/api/v1/debug/quality", s.withAdminAuth(s.handleQuality))
	mux.HandleFunc("/api/v1/debug/capture", s.withAdminAuth(s.handleCapture))
	mux.HandleFunc("/api/v1/debug/evidence", s.withAdminAuth(s.handleEvidence))
	mux.HandleFunc("/api/v1/debug/udp-recovery", s.withAdminAuth(s.handleUDPRecovery))
	if s.wsHub != nil {
		mux.HandleFunc("/api/v1/ws", s.wsHub.handleWS)
	}
	mux.HandleFunc("/", s.withAdminAuth(s.handleNotFound))
	return mux
}

func (s *adminServer) shutdown() {
	if s == nil {
		return
	}
	if s.wsHub != nil {
		s.wsHub.close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *adminServer) stopLocked() {
	s.boundAddr = ""
	if s.http == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), adminShutdownTimeout)
	_ = s.http.Shutdown(ctx)
	cancel()
	s.http = nil
}

func (s *adminServer) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Add("Vary", "Origin")
		next.ServeHTTP(w, r)
	})
}

func (s *adminServer) withAdminCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Add("Vary", "Access-Control-Request-Private-Network")
			w.Header().Add("Vary", "Access-Control-Request-Method")
		}
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if !s.isOriginAllowed(origin) {
				writeAdminAPIError(w, http.StatusForbidden, "origin_forbidden", "origin not allowed")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match")
			w.Header().Set("Access-Control-Expose-Headers", "ETag")
			w.Header().Set("Access-Control-Max-Age", "600")
			if strings.EqualFold(strings.TrimSpace(r.Header.Get("Access-Control-Request-Private-Network")), "true") {
				w.Header().Set("Access-Control-Allow-Private-Network", "true")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		} else if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *adminServer) withAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := clientIPFromRequest(r)
		if s.authLimiter != nil {
			if allowed, retryAfter := s.authLimiter.allow(clientIP); !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				writeAdminAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many authentication failures")
				return
			}
		}
		if !adminBearerOK(r.Header.Get("Authorization"), s.currentSecret()) {
			if s.authLimiter != nil {
				s.authLimiter.recordFailure(clientIP)
			}
			writeAdminAPIError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing bearer token")
			return
		}
		if s.authLimiter != nil {
			s.authLimiter.recordSuccess(clientIP)
		}
		next(w, r)
	}
}

func (s *adminServer) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	writeAdminAPIError(w, http.StatusNotFound, "not_found", "endpoint not found")
}

func (s *adminServer) handleSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	body := adminSystemBody{
		AdminSystemInfo: control.AdminSystemInfo{Version: Version, Running: plane != nil},
	}
	if plane != nil {
		body.AdminSystemInfo = plane.AdminSystemInfo(Version)
	}
	if body.LogLevel == "" && s.log != nil {
		body.LogLevel = s.log.GetLevel().String()
	}
	body.SyncWarning = mihomoWarning(CurrentMihomoStatus())
	syncStatus := s.reloadStatusSnapshot()
	body.ConfigInSync = syncStatus.configInSync
	body.LastReloadError = syncStatus.lastReloadError
	body.ReloadPending = syncStatus.reloadPending
	body.LastReloadRolledBack = syncStatus.lastReloadRolledBack
	if view := CurrentEffectiveConfig(); view != nil {
		body.Generation = view.LoadedAt.UTC().Format("20060102T150405Z")
	}
	writeAdminJSON(w, http.StatusOK, body)
}

func (s *adminServer) handleSystemLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.log == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "logger_unavailable", "logger is unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
	var body adminLogLevelPutBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json")
		return
	}
	rawLevel := strings.ToLower(strings.TrimSpace(body.Level))
	switch rawLevel {
	case "error", "warn", "warning", "info", "debug", "trace":
	default:
		writeAdminAPIError(w, http.StatusBadRequest, "invalid_log_level", "level must be error, warn, info, debug, or trace")
		return
	}
	lvl, err := logrus.ParseLevel(rawLevel)
	if err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid_log_level", "invalid log level")
		return
	}
	s.log.SetLevel(lvl)
	canonical := lvl.String()
	if lvl == logrus.WarnLevel {
		canonical = "warn"
	}
	s.emitWSEvent("log_level_changed", map[string]string{"level": canonical})
	writeAdminJSON(w, http.StatusOK, map[string]string{"level": canonical})
}

func (s *adminServer) buildMetricsBody() any {
	plane := s.currentPlane()
	if plane == nil {
		return control.AdminMetricsSnapshot{
			TimestampMs: time.Now().UnixMilli(),
		}
	}
	return plane.AdminMetricsSnapshot()
}

func (s *adminServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	writeAdminJSON(w, http.StatusOK, plane.AdminMetricsSnapshot())
}

func (s *adminServer) handleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	windowSec := 1800
	if raw := strings.TrimSpace(r.URL.Query().Get("window")); raw != "" {
		v, err := parsePositiveInt(raw, 3600)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid window")
			return
		}
		windowSec = v
	}
	points := 180
	if raw := strings.TrimSpace(r.URL.Query().Get("points")); raw != "" {
		v, err := parsePositiveInt(raw, 720)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid points")
			return
		}
		points = v
	}
	samples := plane.AdminMetricsHistory(windowSec, points)
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"window_sec": windowSec,
		"points":     len(samples),
		"samples":    samples,
	})
}

func (s *adminServer) buildGroupsBody() (any, bool) {
	plane := s.currentPlane()
	if plane == nil {
		return nil, false
	}
	groups := plane.AdminGroups()
	displayNames := CurrentDisplayNames()
	if len(displayNames) > 0 {
		for gi := range groups {
			for mi := range groups[gi].Members {
				if dn := displayNames[groups[gi].Members[mi].Name]; dn != "" {
					groups[gi].Members[mi].DisplayName = dn
				}
			}
		}
	}
	return map[string]any{
		"groups":        groups,
		"display_names": displayNames,
	}, true
}

func (s *adminServer) handleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	body, ok := s.buildGroupsBody()
	if !ok {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	writeAdminJSON(w, http.StatusOK, body)
}

func (s *adminServer) handleGroup(w http.ResponseWriter, r *http.Request) {
	name, action, err := parseAdminGroupPath(r.URL.Path)
	if err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid_group", err.Error())
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	switch action {
	case "probe":
		if r.Method != http.MethodPost {
			writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		if !s.allowGroupProbe(name) {
			w.Header().Set("Retry-After", "3")
			writeAdminAPIError(w, http.StatusTooManyRequests, "probe_cooldown", "probe requested too frequently for group "+name)
			return
		}
		if err := plane.TriggerLatencyChecksForGroup(name); err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "probe_failed", sanitizeAdminError(err))
			return
		}
		writeAdminJSON(w, http.StatusAccepted, map[string]string{"group": name, "action": "probe"})
	case "selection":
		if r.Method != http.MethodPut {
			writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
		var body adminGroupPutBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json")
			return
		}
		body.Member = strings.TrimSpace(body.Member)
		if body.Member == "" {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_member", "member is required")
			return
		}
		if err := plane.SetGroupSelection(name, body.Member); err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "selection_failed", sanitizeAdminError(err))
			return
		}
		s.emitWSEvent("group_selection_changed", map[string]string{"group": name, "member": body.Member})
		writeAdminJSON(w, http.StatusOK, map[string]string{"group": name, "member": body.Member})
	default:
		writeAdminAPIError(w, http.StatusNotFound, "not_found", "group endpoint not found")
	}
}

func (s *adminServer) allowGroupProbe(group string) bool {
	if s == nil {
		return true
	}
	now := time.Now()
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if s.lastProbeByGp == nil {
		s.lastProbeByGp = make(map[string]time.Time)
	}
	if prev, ok := s.lastProbeByGp[group]; ok && now.Sub(prev) < adminProbeCooldown {
		return false
	}
	if len(s.lastProbeByGp) >= 256 {
		for k, ts := range s.lastProbeByGp {
			if now.Sub(ts) >= adminProbeCooldown {
				delete(s.lastProbeByGp, k)
			}
		}
	}
	s.lastProbeByGp[group] = now
	return true
}

func parseConnectionFilterQuery(q url.Values) control.AdminConnectionFilter {
	srcIP := q.Get("src_ip")
	if srcIP == "" {
		srcIP = q.Get("src")
	}
	return control.AdminConnectionFilter{
		Network:  q.Get("network"),
		Outbound: q.Get("outbound"),
		Dialer:   q.Get("dialer"),
		SrcIP:    srcIP,
		DstIP:    q.Get("dst_ip"),
		Domain:   q.Get("domain"),
		Mac:      q.Get("mac"),
		Process:  q.Get("process"),
		Inbound:  q.Get("inbound"),
		Rule:     q.Get("rule"),
		Query:    q.Get("q"),
	}
}

func (s *adminServer) snapshotTrackedConnections(limit int, filter control.AdminConnectionFilter, sortBy, order string) control.AdminConnectionsSnapshot {
	plane := s.currentPlane()
	if plane == nil {
		return control.AdminConnectionsSnapshot{Connections: []control.AdminConnection{}}
	}
	if s.connTracker != nil {
		return s.connTracker.Snapshot(plane, limit, filter, sortBy, order)
	}
	return plane.AdminConnections(limit, filter)
}

func (s *adminServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	q := r.URL.Query()
	limit := 0
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		parsed, err := parsePositiveInt(raw, 1024)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid limit")
			return
		}
		limit = parsed
	}
	filter := parseConnectionFilterQuery(q)
	snap := s.snapshotTrackedConnections(limit, filter, q.Get("sort"), q.Get("order"))
	writeAdminJSON(w, http.StatusOK, snap)
}

func (s *adminServer) handleConnectionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	const prefix = "/api/v1/connections/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == "" || strings.Contains(rest, "/") {
		writeAdminAPIError(w, http.StatusNotFound, "not_found", "connection not found")
		return
	}
	id, err := url.PathUnescape(rest)
	if err != nil || strings.TrimSpace(id) == "" {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid_id", "invalid connection id")
		return
	}
	if !plane.AdminCloseConnection(id) {
		writeAdminAPIError(w, http.StatusNotFound, "not_found", "connection not found")
		return
	}
	if s.connTracker != nil {
		s.connTracker.Invalidate()
	}
	s.emitWSEvent("connections_closed", map[string]any{"closed": 1, "id": id})
	writeAdminJSON(w, http.StatusOK, map[string]any{"closed": true, "id": id})
}

func (s *adminServer) handleConnectionsClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
	var filter control.AdminConnectionFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json")
		return
	}
	if !filter.All && filter.IsEmpty() {
		writeAdminAPIError(w, http.StatusBadRequest, "filter_required", "at least one filter field or all=true is required")
		return
	}
	closed := plane.AdminCloseConnections(filter)
	if s.connTracker != nil {
		s.connTracker.Invalidate()
	}
	if closed > 0 {
		s.emitWSEvent("connections_closed", map[string]any{"closed": closed})
	}
	writeAdminJSON(w, http.StatusOK, map[string]int{"closed": closed})
}

func (s *adminServer) handleKernelConnections(w http.ResponseWriter, r *http.Request) {
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit := 0
		q := r.URL.Query()
		if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
			parsed, err := parsePositiveInt(raw, 1024)
			if err != nil {
				writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid limit")
				return
			}
			limit = parsed
		}
		resolveDomains := false
		if raw := strings.TrimSpace(q.Get("resolve_domains")); raw == "true" || raw == "1" {
			resolveDomains = true
		}
		snap := plane.AdminKernelConnections(limit, q.Get("src"), q.Get("mac"), resolveDomains)
		if snap.Error == "invalid src" || snap.Error == "invalid mac" {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", snap.Error)
			return
		}
		writeAdminJSON(w, http.StatusOK, snap)
	case http.MethodDelete:
		r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
		var req control.AdminKernelCloseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json")
			return
		}
		res, err := plane.AdminCloseKernelConnection(req)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_tuple", err.Error())
			return
		}
		if res.UserspaceClosed && s.connTracker != nil {
			s.connTracker.Invalidate()
		}
		writeAdminJSON(w, http.StatusOK, res)
	default:
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *adminServer) handleClosedFlows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	q := r.URL.Query()
	limit := 0
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		parsed, err := parsePositiveInt(raw, 500)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid limit")
			return
		}
		limit = parsed
	}
	writeAdminJSON(w, http.StatusOK, plane.AdminClosedFlows(limit, parseConnectionFilterQuery(q)))
}

func (s *adminServer) handleTrafficSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	top := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("top")); raw != "" {
		parsed, err := parsePositiveInt(raw, 200)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid top")
			return
		}
		top = parsed
	}
	writeAdminJSON(w, http.StatusOK, plane.AdminTrafficSummary(top))
}

func (s *adminServer) handleTrafficReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	plane.AdminResetTrafficSummary()
	s.emitWSEvent("traffic_reset", nil)
	writeAdminJSON(w, http.StatusOK, map[string]bool{"reset": true})
}

func (s *adminServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		adminConfigWriteMu.Lock()
		body, etag, err := loadAdminConfigCached(s.configDir)
		adminConfigWriteMu.Unlock()
		if err != nil {
			writeAdminAPIError(w, http.StatusInternalServerError, "config_read_failed", sanitizeAdminError(err))
			return
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		writeAdminJSON(w, http.StatusOK, body)
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, adminMaxConfigBytes)
		var body adminConfigBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_json", "invalid json")
			return
		}
		ifMatch := r.Header.Get("If-Match")
		adminConfigWriteMu.Lock()
		if ifMatch != "" {
			currentETag, etagErr := currentAdminConfigETag(s.configDir)
			if etagErr == nil && !checkAdminIfMatch(ifMatch, currentETag) {
				adminConfigWriteMu.Unlock()
				writeAdminAPIError(w, http.StatusPreconditionFailed, "precondition_failed", "configuration changed since last read")
				return
			}
		}
		queued, err := applyAdminConfigLocked(s.configDir, body, s.reload)
		if err == nil {
			s.recordPendingAdminWriteLocked()
		}
		adminConfigWriteMu.Unlock()
		if err != nil {
			status := http.StatusBadRequest
			code := "config_invalid"
			if errors.Is(err, errAdminReloadQueueFull) {
				status = http.StatusConflict
				code = "reload_busy"
			}
			writeAdminAPIError(w, status, code, sanitizeAdminError(err))
			return
		}
		s.emitWSEvent("config_updated", map[string]any{"queued": queued})
		writeAdminJSON(w, http.StatusOK, adminReloadBody{Queued: queued})
	default:
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *adminServer) handleEffectiveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	view := CurrentEffectiveConfig()
	if view == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "config_unavailable", "no configuration is running yet")
		return
	}
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, view.Text())
		return
	}
	writeAdminJSON(w, http.StatusOK, view)
}

func (s *adminServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if s.reload == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "reload_unavailable", "reload is unavailable")
		return
	}
	adminConfigWriteMu.Lock()
	defer adminConfigWriteMu.Unlock()
	if err := validateLoadedAdminConfig(s.configDir); err != nil {
		writeAdminAPIError(w, http.StatusBadRequest, "config_invalid", sanitizeAdminError(err))
		return
	}
	queued := s.reload()
	status := http.StatusAccepted
	if !queued {
		status = http.StatusConflict
	}
	writeAdminJSON(w, status, adminReloadBody{Queued: queued})
}

func (s *adminServer) handleSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	mihomo := CurrentMihomoStatus()
	writeAdminJSON(w, http.StatusOK, adminSourcesBody{
		Mihomo:        mihomo,
		Geodata:       CurrentGeodataStatus(),
		RuleProviders: CurrentRuleProviderStatus(),
		SyncWarning:   mihomoWarning(mihomo),
	})
}

func (s *adminServer) handleSourcesRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	s.sourcesMu.Lock()
	refresher := s.sourcesRefresher
	s.sourcesMu.Unlock()
	if refresher == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "refresh_unavailable", "sources refresher is unavailable")
		return
	}
	if !s.sourcesRefreshing.CompareAndSwap(false, true) {
		writeAdminAPIError(w, http.StatusConflict, "refresh_in_progress", "sources refresh already in progress")
		return
	}
	defer s.sourcesRefreshing.Store(false)

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(adminSourcesRefreshTimeout))
	refreshCtx, cancel := context.WithTimeout(r.Context(), adminSourcesRefreshTimeout)
	defer cancel()

	res, err := refresher(refreshCtx)
	if err != nil {
		writeAdminAPIError(w, http.StatusInternalServerError, "refresh_failed", sanitizeAdminSourceError(err))
		return
	}
	res.Warning = sanitizeAdminSourceMessage(res.Warning)
	mihomo := CurrentMihomoStatus()
	sources := adminSourcesBody{
		Mihomo:        mihomo,
		Geodata:       CurrentGeodataStatus(),
		RuleProviders: CurrentRuleProviderStatus(),
		SyncWarning:   mihomoWarning(mihomo),
	}
	s.emitWSEvent("sources_refreshed", res)
	writeAdminJSON(w, http.StatusOK, map[string]any{
		"refreshed":      true,
		"changed":        res.Changed,
		"used_last_good": res.UsedLastGood,
		"reload_queued":  res.ReloadQueued,
		"warning":        res.Warning,
		"sources":        sources,
	})
}

func (s *adminServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	q := r.URL.Query()
	limit := adminLogDefaultLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		parsed, err := parsePositiveInt(raw, adminLogMaxLimit)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid limit")
			return
		}
		limit = parsed
	}
	minLevel := logrus.TraceLevel
	if rawLvl := strings.TrimSpace(q.Get("level")); rawLvl != "" {
		parsed, err := logrus.ParseLevel(strings.ToLower(rawLvl))
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_log_level", "invalid level")
			return
		}
		minLevel = parsed
	}
	var afterSeq uint64
	if rawAfter := strings.TrimSpace(q.Get("after_seq")); rawAfter != "" {
		parsed, err := strconv.ParseUint(rawAfter, 10, 64)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid after_seq")
			return
		}
		afterSeq = parsed
	}
	entries, latest := s.logRing.Snapshot(limit, minLevel, afterSeq)
	writeAdminJSON(w, http.StatusOK, adminLogsResponseBody{
		Entries:   entries,
		LatestSeq: latest,
	})
}

func (s *adminServer) handleQuality(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "plane_unavailable", "control plane is not ready")
		return
	}
	body := map[string]any{"entries": plane.AdminQuality(r.URL.Query().Get("group"), r.URL.Query().Get("host")), "limit": 256}
	if diagnostics, ok := plane.(interface {
		AdminRecoveryDiagnostics() []outbound.RecoveryDiagnostics
	}); ok {
		body["recovery_diagnostics"] = diagnostics.AdminRecoveryDiagnostics()
		body["recovery_diagnostics_limit"] = 256
	}
	writeAdminJSON(w, http.StatusOK, body)
}

func (s *adminServer) handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	after := uint64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		var err error
		after, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid after cursor")
			return
		}
	}
	plane, ok := s.currentPlane().(interface {
		AdminCapture(uint64) observation.Snapshot
	})
	if !ok {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "capture_unavailable", "capture unavailable")
		return
	}
	writeAdminJSON(w, http.StatusOK, plane.AdminCapture(after))
}

func (s *adminServer) handleUDPRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	after := uint64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		var err error
		after, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid after cursor")
			return
		}
	}
	process := r.URL.Query().Get("process")
	if len(process) > 64 {
		writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid process cursor")
		return
	}
	plane, ok := s.currentPlane().(interface {
		AdminUDPRecovery(uint64, string) control.UDPRecoverySnapshot
	})
	if !ok {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "recovery_unavailable", "UDP recovery diagnostics unavailable")
		return
	}
	writeAdminJSON(w, http.StatusOK, plane.AdminUDPRecovery(after, process))
}

func (s *adminServer) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	after := uint64(0)
	if value := r.URL.Query().Get("after"); value != "" {
		var err error
		after, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			writeAdminAPIError(w, http.StatusBadRequest, "invalid_param", "invalid after cursor")
			return
		}
	}
	plane, ok := s.currentPlane().(interface {
		AdminEvidence(uint64) observation.EvidenceSnapshot
	})
	if !ok {
		writeAdminAPIError(w, http.StatusServiceUnavailable, "evidence_unavailable", "evidence unavailable")
		return
	}
	writeAdminJSON(w, http.StatusOK, plane.AdminEvidence(after))
}

func (s *adminServer) currentPlane() adminPlane {
	if s == nil || s.plane == nil {
		return nil
	}
	return s.plane()
}

func (s *adminServer) warnf(format string, args ...any) {
	if s != nil && s.log != nil {
		s.log.Warnf(format, args...)
	}
}

func (s *adminServer) infof(format string, args ...any) {
	if s != nil && s.log != nil {
		s.log.Infof(format, args...)
	}
}

func adminSecretMatches(candidate, secret string) bool {
	if secret == "" || candidate == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(secret)) == 1
}

func adminBearerOK(header, secret string) bool {
	const prefix = "Bearer "
	if secret == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return adminSecretMatches(got, secret)
}

func clientIPFromRequest(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func parseAdminGroupPath(path string) (name, action string, err error) {
	const prefix = "/api/v1/groups/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", fmt.Errorf("group is required")
	}
	rest := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	if rest == "" {
		return "", "", fmt.Errorf("group is required")
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid group action path")
	}
	name, err = url.PathUnescape(parts[0])
	if err != nil || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("invalid group")
	}
	switch parts[1] {
	case "selection", "probe":
		return name, parts[1], nil
	default:
		return "", "", fmt.Errorf("invalid group action")
	}
}

func writeAdminJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAdminAPIError(w http.ResponseWriter, status int, code, message string) {
	writeAdminJSON(w, status, adminAPIErrorBody{
		Error: adminAPIErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

func parsePositiveInt(raw string, maxVal int) (int, error) {
	n := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid integer")
		}
		n = n*10 + int(r-'0')
		if n > maxVal {
			return maxVal, nil
		}
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid integer")
	}
	return n, nil
}

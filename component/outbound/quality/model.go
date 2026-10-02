/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quality

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ModelWorker is optional shadow evaluation. It cannot publish route changes.
// The queue retains at most one latest summary and one request is in flight.
type modelSummary struct {
	state map[string]any
	at    time.Time
}
type ModelWorker struct {
	ctx               context.Context
	cancel            context.CancelFunc
	pending           chan modelSummary
	done              chan struct{}
	once              sync.Once
	endpoint, keyFile string
	log               func(string, map[string]any)
	client            *http.Client
	caError           error
}

func NewModelWorker(endpoint, keyFile string, log func(string, map[string]any)) *ModelWorker {
	return NewModelWorkerWithCA(endpoint, keyFile, "", log)
}

func NewModelWorkerWithCA(endpoint, keyFile, caFile string, log func(string, map[string]any)) *ModelWorker {
	ctx, cancel := context.WithCancel(context.Background())
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.MaxConnsPerHost = 1
	tr.MaxIdleConnsPerHost = 1
	tr.ResponseHeaderTimeout = 2 * time.Second
	w := &ModelWorker{ctx: ctx, cancel: cancel, pending: make(chan modelSummary, 1), done: make(chan struct{}), endpoint: strings.TrimRight(endpoint, "/"), keyFile: keyFile, log: log, client: &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		certs, err := readModelCA(caFile)
		if err == nil && !pool.AppendCertsFromPEM(certs) {
			err = fmt.Errorf("invalid CA certificate")
		}
		if err != nil {
			w.caError = fmt.Errorf("model CA unavailable")
		} else {
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
	}
	go w.run()
	return w
}

// Bound reads before loading TLS roots; a FIFO must not stall a reload.
func readModelCA(path string) ([]byte, error) {
	before, err := os.Stat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 1<<20 {
		return nil, fmt.Errorf("model CA unavailable")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("model CA unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("model CA unavailable")
	}
	certs, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(certs) > 1<<20 {
		return nil, fmt.Errorf("model CA unavailable")
	}
	return certs, nil
}

// Submit takes ownership of summary; callers must not mutate it afterward.
func (w *ModelWorker) Submit(summary map[string]any) {
	if w == nil || w.ctx.Err() != nil {
		return
	}
	select {
	case w.pending <- modelSummary{summary, time.Now()}:
		return
	default:
	}
	select {
	case <-w.pending:
	default:
	}
	select {
	case w.pending <- modelSummary{summary, time.Now()}:
	default:
	}
}
func (w *ModelWorker) Close() error {
	if w == nil {
		return nil
	}
	w.once.Do(func() { w.cancel(); <-w.done; w.client.CloseIdleConnections() })
	return nil
}
func (w *ModelWorker) emit(reason string, fields map[string]any) {
	if w.log != nil {
		w.log(reason, fields)
	}
}
func (w *ModelWorker) run() {
	defer close(w.done)
	failures := 0
	for {
		select {
		case <-w.ctx.Done():
			return
		case item := <-w.pending:
			if time.Since(item.at) > 2*time.Minute {
				continue
			}
			summary := item.state
			// Read only when enabled and off the traffic path; bounded credential size.
			key, err := readModelKey(w.keyFile)
			var choice string
			var confidence float64
			start := time.Now()
			if err == nil {
				choice, confidence, err = w.predict(key, summary)
			}
			if w.ctx.Err() != nil {
				return
			}
			delay := 2 * time.Minute
			if err != nil {
				failures++
				delay = 10 * time.Second * time.Duration(1<<min(failures-1, 5))
				if delay > 5*time.Minute {
					delay = 5 * time.Minute
				}
				// Never log transport errors: they can contain credential-bearing URLs.
				if failures == 1 || failures == 3 {
					w.emit("laya_unavailable_local_rules_continue", map[string]any{"failures": failures, "retry_after": delay.String(), "error_class": "request_or_protocol"})
				}
			} else {
				w.emit("laya_shadow_comparison", map[string]any{"local_decision": summary["local_decision"], "model_choice": choice, "model_confidence": confidence, "latency_ms": time.Since(start).Milliseconds(), "group": summary["group"], "evidence_id": summary["evidence_id"], "network": summary["network"], "effective_mode": "shadow", "recovered": failures > 0})
				failures = 0
			}
			timer := time.NewTimer(delay)
			select {
			case <-w.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}
func readModelKey(path string) (string, error) {
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return "", fmt.Errorf("credential unavailable")
	}
	f, e := os.Open(path)
	if e != nil {
		return "", fmt.Errorf("credential unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return "", fmt.Errorf("credential invalid")
	}
	key := strings.TrimSpace(string(b))
	for _, line := range strings.Split(key, "\n") {
		if strings.HasPrefix(line, "LAYA_API_KEY=") {
			key = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "LAYA_API_KEY=")), "\"'")
			break
		}
	}
	if key == "" || strings.ContainsAny(key, "\r\n") {
		return "", fmt.Errorf("credential invalid")
	}
	return key, nil
}
func (w *ModelWorker) predict(key string, summary map[string]any) (string, float64, error) {
	if w.caError != nil {
		return "", 0, w.caError
	}
	u, err := url.Parse(w.endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", 0, fmt.Errorf("model endpoint requires HTTPS")
	}
	state := make(map[string]any, len(summary))
	for k, v := range summary {
		if k != "local_decision" && k != "evidence_id" {
			state[k] = v
		}
	}
	body, e := json.Marshal(map[string]any{"state": state, "questions": map[string]any{"assessment": map[string]any{"type": "choice", "instructions": "Classify the supplied local evidence. Recommend verification only, never authorize a route change. Missing measurement validity means insufficient evidence.", "criteria": map[string]string{"verify": "Comparable local evidence supports verifying an alternative.", "keep": "Evidence supports keeping the current path.", "unknown": "Evidence is insufficient or contradictory."}}}})
	if e != nil || len(body) > 16384 {
		return "", 0, fmt.Errorf("invalid input")
	}
	req, e := http.NewRequestWithContext(w.ctx, http.MethodPost, w.endpoint+"/predict", bytes.NewReader(body))
	if e != nil {
		return "", 0, e
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	res, e := w.client.Do(req)
	if e != nil {
		return "", 0, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", 0, fmt.Errorf("status")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	if e != nil || len(b) > 65536 {
		return "", 0, fmt.Errorf("body")
	}
	var out struct {
		Answers map[string]struct {
			Type          string
			Choice        string
			Probabilities map[string]float64
			Confidence    float64
		}
	}
	if json.Unmarshal(b, &out) != nil {
		return "", 0, fmt.Errorf("json")
	}
	a, ok := out.Answers["assessment"]
	if !ok || a.Type != "choice" || len(a.Probabilities) != 3 || !finite(a.Confidence) || a.Confidence < 0 || a.Confidence > 1 {
		return "", 0, fmt.Errorf("schema")
	}
	sum, maximum := 0.0, 0.0
	for _, k := range []string{"verify", "keep", "unknown"} {
		v, ok := a.Probabilities[k]
		if !ok || !finite(v) || v < 0 || v > 1 {
			return "", 0, fmt.Errorf("probability")
		}
		sum += v
		maximum = math.Max(maximum, v)
	}
	v, ok := a.Probabilities[a.Choice]
	if !ok || math.Abs(sum-1) > .002 || v < maximum {
		return "", 0, fmt.Errorf("choice")
	}
	return a.Choice, a.Confidence, nil
}

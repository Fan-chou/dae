/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quality

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestModelProtocolRejectsMalformedAndContradictoryAnswers(t *testing.T) {
	cases := []struct {
		body string
		ok   bool
	}{
		{`{"answers":{"assessment":{"type":"choice","choice":"verify","probabilities":{"verify":0.8,"keep":0.1,"unknown":0.1},"confidence":0.4}}}`, true},
		{`{"answers":{"assessment":{"type":"choice","choice":"keep","probabilities":{"verify":0.8,"keep":0.1,"unknown":0.1},"confidence":0.4}}}`, false},
		{`{"answers":{}}`, false},
		{strings.Repeat("x", 65537), false},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing auth")
				}
				var input struct{ State map[string]any }
				if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
					t.Error(err)
				}
				if _, ok := input.State["local_decision"]; ok {
					t.Error("local answer leaked to model input")
				}
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			w := &ModelWorker{ctx: context.Background(), endpoint: srv.URL, client: srv.Client()}
			_, _, err := w.predict("test-token", map[string]any{"local_decision": "verify"})
			if (err == nil) != tc.ok {
				t.Fatalf("protocol: %v", err)
			}
		})
	}
}
func TestModelCloseCancelsInFlightAndSubmitNeverBlocks(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("LAYA_API_KEY=test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	worker := NewModelWorker(srv.URL, key, nil)
	worker.client.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	defer worker.Close()
	worker.Submit(map[string]any{"n": 1})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request missing")
	}
	start := time.Now()
	for i := 0; i < 1000; i++ {
		worker.Submit(map[string]any{"n": i})
	}
	if time.Since(start) > time.Second {
		t.Fatal("Submit blocked on model")
	}
	done := make(chan struct{})
	go func() { worker.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel request")
	}
}
func TestModelFailureLogsOnlySanitizedClass(t *testing.T) {
	events := make(chan string, 1)
	worker := NewModelWorker("http://127.0.0.1:1", filepath.Join(t.TempDir(), "missing-secret"), func(reason string, _ map[string]any) { events <- reason })
	defer worker.Close()
	worker.Submit(map[string]any{"n": 1})
	select {
	case reason := <-events:
		if reason != "laya_unavailable_local_rules_continue" {
			t.Fatal(reason)
		}
	case <-time.After(time.Second):
		t.Fatal("failure not reported")
	}
}

func TestModelRequiresTLSAndIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	worker := NewModelWorker("http://127.0.0.1:1", "", nil)
	defer worker.Close()
	if worker.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("model reads proxy environment")
	}
	if _, _, err := worker.predict("secret-token", nil); err == nil {
		t.Fatal("plaintext bearer transport accepted")
	}
}

func TestModelCustomCAVerifiesServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"answers":{"assessment":{"type":"choice","choice":"keep","probabilities":{"verify":0.1,"keep":0.8,"unknown":0.1},"confidence":0.8}}}`)
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	worker := NewModelWorkerWithCA(srv.URL, "", ca, nil)
	defer worker.Close()
	if choice, _, err := worker.predict("test-token", nil); err != nil || choice != "keep" {
		t.Fatalf("trusted server: %s %v", choice, err)
	}
	tr := worker.client.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS verification disabled")
	}
	// A trusted certificate still must match the destination hostname.
	worker.client.CloseIdleConnections()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "wrong.example"
	if _, _, err := worker.predict("test-token", nil); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if err := os.WriteFile(ca, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	invalid := NewModelWorkerWithCA(srv.URL, "", ca, nil)
	defer invalid.Close()
	if _, _, err := invalid.predict("test-token", nil); err == nil {
		t.Fatal("invalid CA accepted")
	}
}

func TestModelCAFIFORejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readModelCA(path); err == nil {
		t.Fatal("FIFO CA accepted")
	}
}

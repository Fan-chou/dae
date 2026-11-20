/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

var benchAllowSink bool

func BenchmarkAdminLogRingFire(b *testing.B) {
	b.Run("ZeroSubs_ASCII", func(b *testing.B) {
		ring := newAdminLogRing()
		entry := &logrus.Entry{
			Level:   logrus.InfoLevel,
			Message: "192.168.124.220:34720 <-> example.com:443",
			Data: logrus.Fields{
				"outbound": "proxy",
				"dialer":   "hk-01",
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ring.Fire(entry); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ZeroSubs_UTF8Truncate", func(b *testing.B) {
		ring := newAdminLogRing()
		entry := &logrus.Entry{
			Level:   logrus.InfoLevel,
			Message: "ab" + strings.Repeat("中", 750) + "😀",
			Data: logrus.Fields{
				"detail": "x" + strings.Repeat("字", 200) + "🚀",
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ring.Fire(entry); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ZeroSubs_URIRedact", func(b *testing.B) {
		ring := newAdminLogRing()
		entry := &logrus.Entry{
			Level:   logrus.WarnLevel,
			Message: "dial failed for vless://secret@example.com:443",
			Data: logrus.Fields{
				"uri": "hy2://pass@node.example.com:443?sni=example.com",
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ring.Fire(entry); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("OneSub_NonBlocking", func(b *testing.B) {
		ring := newAdminLogRing()
		ch, cancel := ring.Subscribe(logrus.TraceLevel)
		done := make(chan struct{})
		go func() {
			for {
				select {
				case <-done:
					return
				case <-ch:
				}
			}
		}()
		b.Cleanup(func() {
			cancel()
			close(done)
		})
		entry := &logrus.Entry{
			Level:   logrus.InfoLevel,
			Message: "192.168.124.220:34720 <-> example.com:443",
			Data: logrus.Fields{
				"outbound": "proxy",
				"dialer":   "hk-01",
			},
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := ring.Fire(entry); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAdminAuthLimiterAllowFastPath(b *testing.B) {
	limiter := newAdminAuthLimiter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, _ := limiter.allow("192.168.1.10:54321")
		if ok {
			limiter.recordSuccess("192.168.1.10:54321")
		}
		benchAllowSink = ok
	}
}

func BenchmarkAdminWSEmitEvent(b *testing.B) {
	b.Run("ZeroClients", func(b *testing.B) {
		hub := newAdminWSHub(nil)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hub.emitEvent("traffic_reset", nil)
		}
	})

	b.Run("16Clients", func(b *testing.B) {
		hub := newAdminWSHub(nil)
		clients := make([]*wsClient, 0, wsMaxClients)
		for i := 0; i < wsMaxClients; i++ {
			c := &wsClient{
				hub:    hub,
				sendCh: make(chan []byte, wsSendQueueSize),
				done:   make(chan struct{}),
				subs:   map[string]*wsTopicSub{"events": {}},
			}
			clients = append(clients, c)
			hub.clients[c] = struct{}{}
			go func(cl *wsClient) {
				for {
					select {
					case <-cl.done:
						return
					case <-cl.sendCh:
					}
				}
			}(c)
		}
		b.Cleanup(func() {
			for _, c := range clients {
				c.close()
			}
		})
		payload := map[string]any{"closed": 1}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hub.emitEvent("connections_closed", payload)
		}
	})
}

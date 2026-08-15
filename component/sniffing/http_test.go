/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestSniffHTTPHostHeader(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    string
		wantErr error
	}{
		{
			name: "host header",
			data: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: "example.com",
		},
		{
			name: "host with port",
			data: "GET / HTTP/1.1\r\nHOST: Example.com:443\r\n\r\n",
			want: "Example.com:443",
		},
		{
			name:    "headers complete without host",
			data:    "GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
			wantErr: ErrNotFound,
		},
		{
			name:    "incomplete headers wait",
			data:    "GET / HTTP/1.1\r\nUser-Agent: test\r\n",
			wantErr: ErrNeedMore,
		},
		{
			name:    "request line only waits",
			data:    "GET / HTTP/1.1\r\n",
			wantErr: ErrNeedMore,
		},
		{
			name:    "no newline waits",
			data:    "GET / HTTP/1.1",
			wantErr: ErrNeedMore,
		},
		{
			name: "connect target fallback",
			data: "CONNECT example.com:443 HTTP/1.1\r\n\r\n",
			want: "example.com:443",
		},
		{
			name: "absolute uri fallback",
			data: "GET http://abs.example.org/path HTTP/1.1\r\n\r\n",
			want: "abs.example.org",
		},
		{
			name: "host header wins over connect target",
			data: "CONNECT ignored.example:443 HTTP/1.1\r\nHost: real.example\r\n\r\n",
			want: "real.example",
		},
		{
			name:    "empty host header",
			data:    "GET / HTTP/1.1\r\nHost: \r\n\r\n",
			wantErr: ErrNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sniffHTTPHostHeader([]byte(tt.data))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if got != "" {
					t.Fatalf("host = %q, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want {
				t.Fatalf("host = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSniffTcp_HTTPNeedMoreWaitsForHost(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: delayed.example.com\r\n\r\n")
	sniffer := NewStreamSniffer(&splitReader{data: payload}, 2*time.Second)
	defer func() { _ = sniffer.Close() }()

	got, err := sniffer.SniffTcp()
	if err != nil {
		t.Fatalf("SniffTcp() error = %v", err)
	}
	if got != "delayed.example.com" {
		t.Fatalf("domain = %q, want delayed.example.com", got)
	}
}

func TestSniffTcp_HTTPConnectAndAbsoluteURI(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "connect",
			payload: "CONNECT odin.game.daum.net:443 HTTP/1.1\r\n\r\n",
			want:    "odin.game.daum.net",
		},
		{
			name:    "absolute uri with port",
			payload: "GET http://ip.sb:80/ HTTP/1.0\r\n\r\n",
			want:    "ip.sb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sniffer := NewStreamSniffer(bytes.NewReader([]byte(tt.payload)), 300*time.Millisecond)
			defer func() { _ = sniffer.Close() }()
			got, err := sniffer.SniffTcp()
			if err != nil {
				t.Fatalf("SniffTcp() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("domain = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsIncompleteHttpMethodPrefix(t *testing.T) {
	if !isIncompleteHttpMethodPrefix([]byte("GE")) {
		t.Fatal("GE should wait for GET")
	}
	if !isIncompleteHttpMethodPrefix([]byte("GET")) {
		t.Fatal("GET without space should wait")
	}
	if isIncompleteHttpMethodPrefix([]byte("GOT")) {
		t.Fatal("GOT is not a method prefix")
	}
}

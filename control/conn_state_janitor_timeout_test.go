/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import "testing"

func TestTcpConnStateExpireTimeoutNs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		state             uint8
		seenNonSyn        uint8
		entryGeneration   uint16
		currentGeneration uint16
		aggressive        bool
		want              int64
	}{
		{
			name: "syn-only",
			want: tcpConnStateTimeoutSyn.Nanoseconds(),
		},
		{
			name:       "syn-only aggressive",
			aggressive: true,
			want:       tcpConnStateTimeoutSyn.Nanoseconds() / 2,
		},
		{
			name:              "old generation syn-only padding",
			entryGeneration:   1,
			currentGeneration: 2,
			want:              tcpConnStateTimeoutEstablished.Nanoseconds(),
		},
		{
			name:              "current generation syn-only",
			entryGeneration:   7,
			currentGeneration: 7,
			want:              tcpConnStateTimeoutSyn.Nanoseconds(),
		},
		{
			name:       "established",
			seenNonSyn: 1,
			want:       tcpConnStateTimeoutEstablished.Nanoseconds(),
		},
		{
			name:       "established aggressive",
			seenNonSyn: 1,
			aggressive: true,
			want:       tcpConnStateTimeoutEstablished.Nanoseconds() / 2,
		},
		{
			name:  "closing",
			state: tcpConnStateClosing,
			want:  tcpConnStateTimeoutClosing.Nanoseconds(),
		},
		{
			name:       "closing aggressive",
			state:      tcpConnStateClosing,
			seenNonSyn: 1,
			aggressive: true,
			want:       tcpConnStateTimeoutClosing.Nanoseconds() / 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpConnStateExpireTimeoutNs(tt.state, tt.seenNonSyn, tt.entryGeneration, tt.currentGeneration, tt.aggressive)
			if got != tt.want {
				t.Fatalf("timeout = %d, want %d", got, tt.want)
			}
		})
	}
}

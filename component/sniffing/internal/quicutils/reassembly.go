/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

// CryptoReassembly rebuilds the QUIC CRYPTO stream the way honk does:
// bytes are visible through Assembled only once they form a contiguous
// prefix starting at offset 0. Out-of-order, overlapping, and retransmitted
// fragments sit in pending until they extend that prefix.
type CryptoReassembly struct {
	assembled  []byte
	pending    map[int][]byte
	buffered   int
	overflowed bool
}

// Insert records a CRYPTO fragment at stream offset. Duplicate or fully
// covered fragments are ignored. Data is copied; callers may recycle the
// source buffer afterwards.
func (r *CryptoReassembly) Insert(offset int, data []byte) {
	if r == nil || r.overflowed || len(data) == 0 {
		return
	}
	if offset < 0 {
		return
	}
	assembledLen := len(r.assembled)
	if offset < assembledLen {
		skip := assembledLen - offset
		if skip >= len(data) {
			return
		}
		data = data[skip:]
		offset = assembledLen
	}
	if len(data) > MaxCryptoStream || r.buffered+len(data) > MaxCryptoStream {
		r.markOverflowed()
		return
	}
	owned := make([]byte, len(data))
	copy(owned, data)
	if r.pending == nil {
		r.pending = make(map[int][]byte, 4)
	}
	if old, ok := r.pending[offset]; ok {
		r.buffered -= len(old)
	}
	r.pending[offset] = owned
	r.buffered += len(owned)
	r.drainContiguous()
}

func (r *CryptoReassembly) drainContiguous() {
	for !r.overflowed {
		assembledLen := len(r.assembled)
		bestKey := 0
		found := false
		for offset := range r.pending {
			if offset <= assembledLen && (!found || offset < bestKey) {
				bestKey = offset
				found = true
			}
		}
		if !found {
			return
		}
		data := r.pending[bestKey]
		delete(r.pending, bestKey)
		r.buffered -= len(data)
		skip := 0
		if bestKey < assembledLen {
			skip = assembledLen - bestKey
			if skip >= len(data) {
				continue
			}
		}
		r.assembled = append(r.assembled, data[skip:]...)
		if len(r.assembled) > MaxCryptoStream {
			r.markOverflowed()
			return
		}
	}
}

func (r *CryptoReassembly) markOverflowed() {
	r.overflowed = true
	r.pending = nil
	r.buffered = 0
	r.assembled = r.assembled[:0]
}

// Assembled is the contiguous CRYPTO prefix starting at offset 0.
func (r *CryptoReassembly) Assembled() []byte {
	if r == nil {
		return nil
	}
	return r.assembled
}

func (r *CryptoReassembly) IsEmpty() bool {
	return r == nil || (len(r.assembled) == 0 && len(r.pending) == 0)
}

func (r *CryptoReassembly) Overflowed() bool {
	return r != nil && r.overflowed
}

// Reset drops assembled and pending state so the sniffer can be pooled.
func (r *CryptoReassembly) Reset() {
	if r == nil {
		return
	}
	r.assembled = r.assembled[:0]
	r.pending = nil
	r.buffered = 0
	r.overflowed = false
}

func (r *CryptoReassembly) exportFrames() []*CryptoFrameOffset {
	if r == nil || r.overflowed {
		return nil
	}
	n := len(r.pending)
	if len(r.assembled) > 0 {
		n++
	}
	if n == 0 {
		return nil
	}
	out := make([]*CryptoFrameOffset, 0, n)
	if len(r.assembled) > 0 {
		o := AcquireCryptoFrameOffset()
		o.UpperAppOffset = 0
		o.Data = r.assembled
		out = append(out, o)
	}
	for offset, data := range r.pending {
		o := AcquireCryptoFrameOffset()
		o.UpperAppOffset = offset
		o.Data = data
		out = append(out, o)
	}
	return out
}

// ClientHelloParse is the honk ClientHelloParse analogue.
type ClientHelloParse uint8

const (
	// ClientHelloIncomplete: not enough CRYPTO data yet.
	ClientHelloIncomplete ClientHelloParse = iota
	// ClientHelloComplete: the handshake message is fully buffered.
	ClientHelloComplete
	// ClientHelloInvalid: the stream is not a well-formed ClientHello.
	ClientHelloInvalid
)

// ClassifyClientHello inspects the CRYPTO prefix as a TLS handshake message
// (RFC 9001 §4.1.3: no TLS record header). SNI extraction is left to the
// caller once the status is Complete.
func ClassifyClientHello(stream []byte) (ClientHelloParse, int) {
	if len(stream) < 4 {
		return ClientHelloIncomplete, 0
	}
	if stream[0] != 0x01 { // HandshakeType client_hello
		return ClientHelloInvalid, 0
	}
	hsLen := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if hsLen < 0 || hsLen > MaxCryptoStream {
		return ClientHelloInvalid, 0
	}
	need := 4 + hsLen
	if len(stream) < need {
		return ClientHelloIncomplete, need
	}
	return ClientHelloComplete, need
}

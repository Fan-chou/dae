/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"bytes"
	"errors"
	"testing"
)

func TestCryptoReassemblyOutOfOrderAndDuplicate(t *testing.T) {
	var reasm CryptoReassembly
	reasm.Insert(10, []byte("defghij"))
	if len(reasm.Assembled()) != 0 {
		t.Fatal("prefix must stay empty until offset 0 arrives")
	}
	reasm.Insert(0, []byte("abc"))
	if !bytes.Equal(reasm.Assembled(), []byte("abc")) {
		t.Fatalf("got %q", reasm.Assembled())
	}
	reasm.Insert(3, []byte("defgh"))
	if !bytes.Equal(reasm.Assembled(), []byte("abcdefgh")) {
		t.Fatalf("got %q", reasm.Assembled())
	}
	reasm.Insert(0, []byte("abc"))
	if !bytes.Equal(reasm.Assembled(), []byte("abcdefgh")) {
		t.Fatalf("duplicate must not change prefix: %q", reasm.Assembled())
	}
	reasm.Insert(5, []byte("fghij"))
	if !bytes.Equal(reasm.Assembled(), []byte("abcdefghijdefghij")) {
		t.Fatalf("overlap extend got %q", reasm.Assembled())
	}
}

func TestCryptoReassemblySameOffsetKeepsLonger(t *testing.T) {
	var reasm CryptoReassembly
	reasm.Insert(10, []byte("ab"))
	reasm.Insert(10, []byte("abcdef"))
	reasm.Insert(10, []byte("xy"))
	reasm.Insert(0, []byte("0123456789"))
	if !bytes.Equal(reasm.Assembled(), []byte("0123456789abcdef")) {
		t.Fatalf("same-offset must keep the longer fragment: %q", reasm.Assembled())
	}
}

func TestCryptoReassemblyHoleStaysPending(t *testing.T) {
	var reasm CryptoReassembly
	reasm.Insert(0, []byte("abc"))
	reasm.Insert(4, []byte("ef"))
	if !bytes.Equal(reasm.Assembled(), []byte("abc")) {
		t.Fatalf("hole must not be skipped: %q", reasm.Assembled())
	}
	reasm.Insert(3, []byte("d"))
	if !bytes.Equal(reasm.Assembled(), []byte("abcdef")) {
		t.Fatalf("filling the hole got %q", reasm.Assembled())
	}
}

func TestCryptoReassemblyOverflow(t *testing.T) {
	var reasm CryptoReassembly
	reasm.Insert(0, make([]byte, MaxCryptoStream+1))
	if !reasm.Overflowed() {
		t.Fatal("expected overflow")
	}
	if len(reasm.Assembled()) != 0 {
		t.Fatal("overflowed reassembly must drop the prefix")
	}
	reasm.Insert(0, []byte("abc"))
	if len(reasm.Assembled()) != 0 {
		t.Fatal("inserts after overflow must be ignored")
	}
}

func TestCollectCryptoFramesSkipsAckThenReadsCrypto(t *testing.T) {
	// ACK (type 0x02) with all-zero 1-byte varints, then CRYPTO offset 0 "hello".
	payload := []byte{
		Quic_FrameType_Ack, 0x00, 0x00, 0x00, 0x00,
		Quic_FrameType_Crypto, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o',
	}
	var reasm CryptoReassembly
	if err := CollectCryptoFrames(payload, &reasm); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reasm.Assembled(), []byte("hello")) {
		t.Fatalf("got %q, want hello", reasm.Assembled())
	}
}

func TestCollectCryptoFramesSkipsAckEcnAndConnectionClose(t *testing.T) {
	payload := []byte{
		Quic_FrameType_AckEcn, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		Quic_FrameType_Crypto, 0x00, 0x03, 's', 'n', 'i',
		Quic_FrameType_ConnectionClose, 0x00, 0x00, 0x00, // error, frame type, reason len 0
		Quic_FrameType_Ping,
	}
	var reasm CryptoReassembly
	if err := CollectCryptoFrames(payload, &reasm); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reasm.Assembled(), []byte("sni")) {
		t.Fatalf("got %q", reasm.Assembled())
	}
	if !reasm.Closed() {
		t.Fatal("CONNECTION_CLOSE must mark reassembly closed")
	}
}

func TestCollectCryptoFramesUnknownStopsButKeepsCrypto(t *testing.T) {
	payload := []byte{
		Quic_FrameType_Crypto, 0x00, 0x02, 'o', 'k',
		0x08, // STREAM is illegal in Initial; walk must stop
		Quic_FrameType_Crypto, 0x02, 0x02, 'n', 'o',
	}
	var reasm CryptoReassembly
	if err := CollectCryptoFrames(payload, &reasm); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reasm.Assembled(), []byte("ok")) {
		t.Fatalf("got %q, want ok (second CRYPTO must not be read)", reasm.Assembled())
	}
}

func TestCollectCryptoFramesUnknownOnlyIsNotError(t *testing.T) {
	var reasm CryptoReassembly
	if err := CollectCryptoFrames([]byte{0x08}, &reasm); err != nil {
		t.Fatal(err)
	}
	if !reasm.IsEmpty() {
		t.Fatal("expected empty reassembly")
	}
}

func TestClassifyClientHello(t *testing.T) {
	st, _ := ClassifyClientHello([]byte{0x01, 0x00, 0x00})
	if st != ClientHelloIncomplete {
		t.Fatalf("short prefix: %v", st)
	}
	st, _ = ClassifyClientHello([]byte{0x02, 0x00, 0x00, 0x01, 0x00})
	if st != ClientHelloInvalid {
		t.Fatalf("non-hello: %v", st)
	}
	body := make([]byte, 8)
	hs := []byte{0x01, 0x00, 0x00, byte(len(body))}
	hs = append(hs, body...)
	st, n := ClassifyClientHello(hs[:6])
	if st != ClientHelloIncomplete {
		t.Fatalf("partial hello: %v n=%d", st, n)
	}
	st, n = ClassifyClientHello(hs)
	if st != ClientHelloComplete || n != len(hs) {
		t.Fatalf("complete: st=%v n=%d", st, n)
	}
}

func TestReassembleCryptosAckThenCrypto(t *testing.T) {
	payload := []byte{
		Quic_FrameType_Ack, 0x00, 0x00, 0x00, 0x00,
		Quic_FrameType_Crypto, 0x00, 0x04, 'q', 'u', 'i', 'c',
	}
	frames, err := ReassembleCryptos(nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer ReleaseCryptoFrameOffsets(frames)
	if len(frames) != 1 || !bytes.Equal(frames[0].Data, []byte("quic")) {
		t.Fatalf("frames=%v", frames)
	}
}

func TestExtractCryptoFrameOffsetAckIsNotUnknown(t *testing.T) {
	remainder := []byte{Quic_FrameType_Ack, 0x00, 0x00, 0x00, 0x00}
	o, n, err := ExtractCryptoFrameOffset(remainder, 0)
	if err != nil {
		t.Fatal(err)
	}
	if o != nil {
		t.Fatal("ACK must not yield a CRYPTO offset")
	}
	if n != len(remainder) {
		t.Fatalf("consumed %d, want %d", n, len(remainder))
	}
}

func TestSkipAckFrameRejectsHugeRangeCount(t *testing.T) {
	// 2-byte QUIC varint 0x4041 = 65 additional ACK ranges.
	body := []byte{0x00, 0x00, 0x40, 0x41, 0x00}
	_, err := skipAckFrame(body, false)
	if !errors.Is(err, ErrOutOfRange) {
		t.Fatalf("got %v, want ErrOutOfRange", err)
	}
}

func TestExtractCryptoFrameOffsetUnknown(t *testing.T) {
	_, _, err := ExtractCryptoFrameOffset([]byte{0x08}, 0)
	if !errors.Is(err, ErrUnknownFrameType) {
		t.Fatalf("got %v", err)
	}
}

func BenchmarkCryptoReassemblyInsertDrain(b *testing.B) {
	frag0 := bytes.Repeat([]byte("a"), 40)
	frag1 := bytes.Repeat([]byte("b"), 80)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var reasm CryptoReassembly
		reasm.Insert(40, frag1)
		reasm.Insert(0, frag0)
		if len(reasm.Assembled()) != 120 {
			b.Fatal(len(reasm.Assembled()))
		}
	}
}

func BenchmarkCollectCryptoFramesAckThenCrypto(b *testing.B) {
	payload := []byte{
		Quic_FrameType_Ack, 0x00, 0x00, 0x00, 0x00,
		Quic_FrameType_Crypto, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o',
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var reasm CryptoReassembly
		if err := CollectCryptoFrames(payload, &reasm); err != nil {
			b.Fatal(err)
		}
	}
}

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package quicutils

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	ErrUnknownFrameType = fmt.Errorf("unknown frame type")
	ErrOutOfRange       = fmt.Errorf("index out of range")
)

const (
	Quic_FrameType_Padding          = 0
	Quic_FrameType_Ping             = 1
	Quic_FrameType_Ack              = 0x02
	Quic_FrameType_AckEcn           = 0x03
	Quic_FrameType_Crypto           = 6
	Quic_FrameType_ConnectionClose  = 0x1c
	Quic_FrameType_ConnectionClose2 = 0x1d
)

// MaxCryptoStream is the honk-aligned cap on the reassembled CRYPTO stream
// (ClientHello is well under 4 KiB). Hostile flows cannot grow it further.
const MaxCryptoStream = 64 * 1024

type CryptoFrameOffset struct {
	UpperAppOffset int
	// Offset of data in quic payload.
	Data []byte
}

// cryptoFrameOffsetPool recycles *CryptoFrameOffset structs across QUIC
// packets so each crypto frame does not allocate a new struct. Data is cleared
// on release; the returned struct never carries stale plaintext slices.
//
// Lifetime invariant: Insert copies fragment bytes into CryptoReassembly.
// A pooled CryptoFrameOffset is released after Insert; it must not alias
// sniffer plaintext after CollectCryptoFrames returns.
var cryptoFrameOffsetPool = sync.Pool{
	New: func() any { return &CryptoFrameOffset{} },
}

// AcquireCryptoFrameOffset returns a zeroed *CryptoFrameOffset from the pool.
func AcquireCryptoFrameOffset() *CryptoFrameOffset {
	return cryptoFrameOffsetPool.Get().(*CryptoFrameOffset)
}

// ReleaseCryptoFrameOffset returns one struct to the pool after clearing Data.
func ReleaseCryptoFrameOffset(o *CryptoFrameOffset) {
	if o == nil {
		return
	}
	o.UpperAppOffset = 0
	o.Data = nil
	cryptoFrameOffsetPool.Put(o)
}

// ReleaseCryptoFrameOffsets returns a slice of structs to the pool. Callers
// must not reference the structs or the slice afterwards.
func ReleaseCryptoFrameOffsets(offsets []*CryptoFrameOffset) {
	for _, o := range offsets {
		ReleaseCryptoFrameOffset(o)
	}
}

func ReassembleCryptos(offsets []*CryptoFrameOffset, newPayload []byte) (newOffsets []*CryptoFrameOffset, err error) {
	var reasm CryptoReassembly
	for _, o := range offsets {
		if o == nil {
			continue
		}
		reasm.Insert(o.UpperAppOffset, o.Data)
	}
	if err = CollectCryptoFrames(newPayload, &reasm); err != nil {
		return nil, err
	}
	return reasm.exportFrames(), nil
}

// CollectCryptoFrames walks Initial plaintext frames (RFC 9000 §17.2.2) and
// inserts CRYPTO payloads into reasm. PADDING, PING, ACK, ACK_ECN and
// CONNECTION_CLOSE are skipped. An unknown frame stops the walk; fragments
// already collected are kept (honk collect_crypto_frames).
func CollectCryptoFrames(payload []byte, reasm *CryptoReassembly) error {
	if reasm == nil {
		return nil
	}
	for iNextFrame := 0; iNextFrame < len(payload); {
		offset, frameSize, err := ExtractCryptoFrameOffset(payload[iNextFrame:], iNextFrame)
		if err != nil {
			if errors.Is(err, ErrUnknownFrameType) || errors.Is(err, ErrOutOfRange) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if offset != nil {
			reasm.Insert(offset.UpperAppOffset, offset.Data)
			ReleaseCryptoFrameOffset(offset)
		}
		if frameSize <= 0 {
			return nil
		}
		iNextFrame += frameSize
	}
	return nil
}

func ExtractCryptoFrameOffset(remainder []byte, transportOffset int) (offset *CryptoFrameOffset, frameSize int, err error) {
	if len(remainder) == 0 {
		return nil, 0, fmt.Errorf("frame has no length: %w", ErrOutOfRange)
	}
	frameType, nextField, err := BigEndianUvarint(remainder)
	if err != nil {
		return nil, 0, err
	}
	switch frameType {
	case Quic_FrameType_Ping:
		return nil, nextField, nil
	case Quic_FrameType_Padding:
		for ; nextField < len(remainder) && remainder[nextField] == 0; nextField++ {
		}
		return nil, nextField, nil
	case Quic_FrameType_Ack, Quic_FrameType_AckEcn:
		n, err := skipAckFrame(remainder[nextField:], frameType == Quic_FrameType_AckEcn)
		if err != nil {
			return nil, 0, err
		}
		return nil, nextField + n, nil
	case Quic_FrameType_Crypto:
		offset, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return nil, 0, err
		}
		nextField += n

		length, n, err := BigEndianUvarint(remainder[nextField:])
		if err != nil {
			return nil, 0, err
		}
		nextField += n
		if nextField+int(length) > len(remainder) {
			return nil, 0, fmt.Errorf("crypto frame data out of range: %w", ErrOutOfRange)
		}

		o := AcquireCryptoFrameOffset()
		o.UpperAppOffset = int(offset)
		o.Data = remainder[nextField : nextField+int(length)]
		return o, nextField + int(length), nil
	case Quic_FrameType_ConnectionClose, Quic_FrameType_ConnectionClose2:
		n, err := skipConnectionCloseFrame(remainder[nextField:], frameType == Quic_FrameType_ConnectionClose)
		if err != nil {
			return nil, 0, err
		}
		return nil, nextField + n, nil
	default:
		return nil, 0, fmt.Errorf("%w: %v", ErrUnknownFrameType, frameType)
	}
}

func skipAckFrame(body []byte, hasECN bool) (int, error) {
	pos := 0
	_, n, err := BigEndianUvarint(body[pos:]) // largest acknowledged
	if err != nil {
		return 0, err
	}
	pos += n
	_, n, err = BigEndianUvarint(body[pos:]) // ACK delay
	if err != nil {
		return 0, err
	}
	pos += n
	rangeCount, n, err := BigEndianUvarint(body[pos:])
	if err != nil {
		return 0, err
	}
	pos += n
	_, n, err = BigEndianUvarint(body[pos:]) // first ACK range
	if err != nil {
		return 0, err
	}
	pos += n
	for i := uint64(0); i < rangeCount; i++ {
		_, n, err = BigEndianUvarint(body[pos:]) // gap
		if err != nil {
			return 0, err
		}
		pos += n
		_, n, err = BigEndianUvarint(body[pos:]) // ACK range length
		if err != nil {
			return 0, err
		}
		pos += n
	}
	if hasECN {
		for i := 0; i < 3; i++ {
			_, n, err = BigEndianUvarint(body[pos:])
			if err != nil {
				return 0, err
			}
			pos += n
		}
	}
	return pos, nil
}

func skipConnectionCloseFrame(body []byte, hasFrameType bool) (int, error) {
	pos := 0
	_, n, err := BigEndianUvarint(body[pos:]) // error code
	if err != nil {
		return 0, err
	}
	pos += n
	if hasFrameType {
		_, n, err = BigEndianUvarint(body[pos:]) // triggering frame type
		if err != nil {
			return 0, err
		}
		pos += n
	}
	reasonLen, n, err := BigEndianUvarint(body[pos:])
	if err != nil {
		return 0, err
	}
	pos += n
	end := pos + int(reasonLen)
	if end > len(body) {
		return 0, fmt.Errorf("connection close reason out of range: %w", ErrOutOfRange)
	}
	return end, nil
}

var (
	ErrMissingCrypto = fmt.Errorf("missing crypto frame")
)

type Locator interface {
	Range(i, j int) ([]byte, error)
	Slice(i, j int) (Locator, error)
	At(i int) (byte, error)
	Len() int
	Bytes() ([]byte, error)
}

// LinearLocator only searches forward and have no boundary check.
type LinearLocator struct {
	left      int
	length    int
	iOuter    int
	baseEnd   int
	baseStart int
	baseData  []byte
	o         []*CryptoFrameOffset
}

func NewLinearLocator(o []*CryptoFrameOffset) *LinearLocator {
	l := &LinearLocator{}
	l.Reset(o)
	return l
}

// Reset reinitializes an existing *LinearLocator for a new set of crypto frame
// offsets, avoiding the allocation that NewLinearLocator performs. Callers that
// retain the locator across sniffing calls (e.g. a pooled Sniffer) should use
// this instead of constructing a new locator each time.
func (l *LinearLocator) Reset(o []*CryptoFrameOffset) {
	l.left = 0
	l.iOuter = 0
	if len(o) == 0 {
		l.length = 0
		l.baseData = nil
		l.baseStart = 0
		l.baseEnd = 0
		l.o = nil
		return
	}
	l.length = o[len(o)-1].UpperAppOffset + len(o[len(o)-1].Data)
	l.baseData = o[0].Data
	l.baseStart = o[0].UpperAppOffset
	l.baseEnd = o[0].UpperAppOffset + len(o[0].Data)
	l.o = o
}

func (l *LinearLocator) relocate(i int) error {
	// Relocate ll.iOuter.
	for i >= l.baseEnd {
		if l.iOuter+1 >= len(l.o) {
			return ErrMissingCrypto
		}
		l.iOuter++
		l.baseData = l.o[l.iOuter].Data
		l.baseStart = l.o[l.iOuter].UpperAppOffset
		l.baseEnd = l.baseStart + len(l.baseData)
	}
	if i < l.baseStart {
		return ErrMissingCrypto
	}
	return nil
}

func (l *LinearLocator) Range(i, j int) ([]byte, error) {
	if i == j {
		return []byte{}, nil
	}
	if len(l.o) == 0 {
		return nil, ErrMissingCrypto
	}
	size := j - i

	// We find bytes including i and j, so we should sub j with 1.
	i += l.left
	j += l.left - 1
	if err := l.relocate(i); err != nil {
		return nil, err
	}

	// Linearly copy.

	if j < l.baseEnd {
		// In the same block, no copy needed.
		return l.baseData[i-l.baseStart : j-l.baseStart+1], nil
	}

	b := make([]byte, size)
	k := 0
	for j >= l.baseEnd {
		n := copy(b[k:], l.baseData[i-l.baseStart:])
		k += n
		i += n
		if l.iOuter+1 >= len(l.o) || l.o[l.iOuter].UpperAppOffset+len(l.o[l.iOuter].Data) != l.o[l.iOuter+1].UpperAppOffset {
			// Some crypto is missing.
			return nil, ErrMissingCrypto
		}
		l.iOuter++
		l.baseData = l.o[l.iOuter].Data
		l.baseStart = l.o[l.iOuter].UpperAppOffset
		l.baseEnd = l.baseStart + len(l.baseData)
	}
	copy(b[k:], l.baseData[i-l.baseStart:j-l.baseStart+1])
	return b, nil
}

func (l *LinearLocator) At(i int) (byte, error) {
	if len(l.o) == 0 {
		return 0, ErrMissingCrypto
	}
	i += l.left

	if err := l.relocate(i); err != nil {
		return 0, err
	}
	b := l.baseData[i-l.baseStart]
	return b, nil
}

func (l *LinearLocator) Slice(i, j int) (Locator, error) {
	// We do not care about right.
	newLL := *l
	newLL.left += i
	newLL.length = j - i + 1
	return &newLL, nil
}

func (l *LinearLocator) Bytes() ([]byte, error) {
	return l.Range(0, l.length)
}

var _ Locator = &LinearLocator{}

func (l *LinearLocator) Len() int {
	return l.length
}

type BuiltinBytesLocator []byte

func (l BuiltinBytesLocator) Range(i, j int) ([]byte, error) {
	return l[i:j], nil
}
func (l BuiltinBytesLocator) At(i int) (byte, error) {
	return l[i], nil
}
func (l BuiltinBytesLocator) Slice(i, j int) (Locator, error) {
	return l[i:j], nil
}
func (l BuiltinBytesLocator) Len() int {
	return len(l)
}
func (l BuiltinBytesLocator) Bytes() ([]byte, error) {
	return l, nil
}

var _ Locator = BuiltinBytesLocator{}

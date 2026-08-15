/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"encoding/binary"
	"errors"
	"io/fs"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
)

const (
	QuicFlag_PacketNumberLength = 0
	QuicFlag_Reserved           = 2
	QuicFlag_LongPacketType     = 4
	QuicFlag_FixedBit           = 6
	QuicFlag_HeaderForm         = 7
)
const (
	QuicFlag_HeaderForm_LongHeader    = 1
	QuicFlag_LongPacketType_Initial   = 0
	QuicFlag_LongPacketType_InitialV2 = 1
)

const (
	QuicVersion1 = 0x00000001
	QuicVersion2 = 0x6b3343cf
)

func quicInitialPacketTypeForVersion(version uint32) byte {
	if v, err := quicutils.ParseVersion(version); err == nil && v == quicutils.Version_V2 {
		return QuicFlag_LongPacketType_InitialV2
	}
	return QuicFlag_LongPacketType_Initial
}

func isQuicInitialLongHeader(buf []byte) bool {
	const minQuicInitialHeaderLen = 7
	if len(buf) < minQuicInitialHeaderLen {
		return false
	}
	if ((buf[0] >> QuicFlag_HeaderForm) & 0b1) != QuicFlag_HeaderForm_LongHeader {
		return false
	}
	version := binary.BigEndian.Uint32(buf[1:5])
	packetType := (buf[0] >> QuicFlag_LongPacketType) & 0b11
	return packetType == quicInitialPacketTypeForVersion(version)
}

// IsLikelyQuicInitialPacket checks if the buffer appears to be a QUIC Initial packet.
// It validates the Long Header format and Initial packet type.
//
// FixedBit is NOT strictly checked to maintain compatibility with various QUIC
// implementations (e.g., Nginx, Cloudflare). Packet type bits are version-aware:
// RFC 9000 v1 Initial is 0b00, RFC 9369 v2 Initial is 0b01. Unknown versions
// keep the v1 mapping so drafts that reuse v1 type bits still sniff.
func IsLikelyQuicInitialPacket(buf []byte) bool {
	return isQuicInitialLongHeader(buf)
}

func (s *Sniffer) SniffQuic() (d string, err error) {
	nextBlock := s.buf.Bytes()[s.quicNextRead:]
	isQuic := false
	for {
		s.quicCryptos, nextBlock, err = sniffQuicBlock(s, s.quicCryptos, nextBlock)
		if err != nil {
			// If block is not a quic block, return it.
			if errors.Is(err, ErrNotApplicable) {
				// But if we have found quic block before, correct it.
				if isQuic {
					// Unexpected non-block
					break
				}
				return "", err
			}
			if errors.Is(err, fs.ErrClosed) {
				// ConnectionClose sniffed.
				return "", ErrNotFound
			}
			// The code should NOT run here.
			return "", err
		}
		// Should be quic block.
		isQuic = true
		if len(nextBlock) == 0 {
			break
		}
	}
	// Is quic.
	s.quicNextRead = s.buf.Len()
	// Reuse the per-Sniffer LinearLocator across SniffQuic calls instead of
	// allocating a new one each time (NewLinearLocator was a leading QUIC
	// allocation). Reset repoints it at the current crypto frame offsets.
	if s.quicLocator == nil {
		s.quicLocator = quicutils.NewLinearLocator(s.quicCryptos)
	} else {
		s.quicLocator.Reset(s.quicCryptos)
	}
	sni, err := extractSniFromTls(s.quicLocator)
	if err != nil {
		s.needMore = true
		return "", ErrNotFound
	}
	return sni, nil
}

func sniffQuicBlock(s *Sniffer, cryptos []*quicutils.CryptoFrameOffset, buf []byte) (new []*quicutils.CryptoFrameOffset, next []byte, err error) {
	// QUIC: A UDP-Based Multiplexed and Secure Transport
	// https://datatracker.ietf.org/doc/html/rfc9000#name-initial-packet
	const dstConnIdPos = 6
	boundary := dstConnIdPos
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	// Check flag.
	// Long header: 4 bits masked
	// High 4 bits are not protected, so we can access QuicFlag_HeaderForm and QuicFlag_LongPacketType without decryption.
	if !isQuicInitialLongHeader(buf) {
		return cryptos, nil, ErrNotApplicable
	}

	// Skip version. DecryptQuic_ reads it for the Initial salt.

	destConnIdLength := int(buf[boundary-1])
	boundary += destConnIdLength + 1 // +1 because next field has 1B length
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	destConnId := buf[dstConnIdPos : dstConnIdPos+destConnIdLength]

	srcConnIdLength := int(buf[boundary-1])
	boundary += srcConnIdLength + quicutils.MaxVarintLen64 // The next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	tokenLength, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return cryptos, nil, ErrNotApplicable
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n      // Correct boundary.
	boundary += int(tokenLength) + quicutils.MaxVarintLen64 // Next fields may have quic.MaxVarintLen64 bytes length
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	// https://datatracker.ietf.org/doc/html/rfc9000#name-variable-length-integer-enc
	length, n, err := quicutils.BigEndianUvarint(buf[boundary-quicutils.MaxVarintLen64:])
	if err != nil {
		return cryptos, nil, ErrNotApplicable
	}
	boundary = boundary - quicutils.MaxVarintLen64 + n // Correct boundary.
	blockEnd := boundary + int(length)
	if len(buf) < blockEnd {
		return cryptos, nil, ErrNotApplicable
	}
	boundary += quicutils.MaxPacketNumberLength
	if len(buf) < boundary {
		return cryptos, nil, ErrNotApplicable
	}
	header := buf[:boundary]
	// Decrypt protected Packets.
	// https://datatracker.ietf.org/doc/html/rfc9000#packet-protected

	// This function will modify the packet in place, thus we should save the first byte and MaxPacketNumberLength
	// and recover it later.
	firstByte := header[0]
	rawPacketNumber := pool.Get(quicutils.MaxPacketNumberLength)
	copy(rawPacketNumber, header[boundary-quicutils.MaxPacketNumberLength:])
	defer func() {
		header[0] = firstByte
		copy(header[boundary-quicutils.MaxPacketNumberLength:], rawPacketNumber)
		pool.Put(rawPacketNumber)
	}()
	plaintext, err := quicutils.DecryptQuic_(buf, boundary-quicutils.MaxPacketNumberLength, blockEnd, destConnId)
	if err != nil {
		return cryptos, nil, ErrNotApplicable
	}
	s.quicPlaintexts = append(s.quicPlaintexts, plaintext)
	// Now, we confirm it is exact a quic frame.
	// After here, we should not return NotApplicableError.
	// And we should return nextFrame.
	if new, err = quicutils.ReassembleCryptos(cryptos, plaintext); err != nil {
		if errors.Is(err, fs.ErrClosed) {
			return cryptos, nil, err
		}
		return cryptos, buf[blockEnd:], ErrNotApplicable
	}
	return new, buf[blockEnd:], nil
}

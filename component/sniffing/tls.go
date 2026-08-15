/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"encoding/binary"
	"strings"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
)

const (
	ContentType_HandShake                byte   = 22
	HandShakeType_Hello                  byte   = 1
	TlsExtension_ServerName              uint16 = 0
	TlsExtension_ServerNameType_HostName byte   = 0

	AssumedTlsClientHelloMaxLength = 4096
)

func clientHelloComplete(payload []byte) bool {
	if len(payload) < 4 || payload[0] != HandShakeType_Hello {
		return false
	}
	n := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	return n >= 0 && len(payload) >= 4+n
}

func (s *Sniffer) tlsClientHelloPayload() ([]byte, error) {
	buf := s.buf.Bytes()
	if len(buf) == 0 || buf[0] != ContentType_HandShake {
		return nil, ErrNotApplicable
	}
	if len(buf) < 5 {
		return nil, ErrNeedMore
	}
	if buf[1] != 0x03 {
		return nil, ErrNotApplicable
	}

	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if len(buf) < 5+recLen {
		return nil, ErrNeedMore
	}
	first := buf[5 : 5+recLen]
	if len(first) > 0 && first[0] != HandShakeType_Hello {
		return nil, ErrNotApplicable
	}
	if clientHelloComplete(first) {
		return first, nil
	}

	// ClientHello can span TLS records. Concatenate handshake payloads until
	// the 3-byte handshake length is satisfied, instead of parsing only the
	// first record (which misses SNI that landed in a later record).
	var payload []byte
	off := 0
	for {
		if len(buf)-off < 5 {
			return nil, ErrNeedMore
		}
		if buf[off] != ContentType_HandShake || buf[off+1] != 0x03 {
			if clientHelloComplete(payload) {
				return payload, nil
			}
			if len(payload) == 0 {
				return nil, ErrNotApplicable
			}
			return nil, ErrNotApplicable
		}
		n := int(binary.BigEndian.Uint16(buf[off+3 : off+5]))
		if len(buf)-off < 5+n {
			return nil, ErrNeedMore
		}
		payload = append(payload, buf[off+5:off+5+n]...)
		off += 5 + n
		if clientHelloComplete(payload) {
			return payload, nil
		}
	}
}

// SniffTls only supports tls1.2, tls1.3
func (s *Sniffer) SniffTls() (d string, err error) {
	// The Transport Layer Security (TLS) Protocol Version 1.3
	// https://www.rfc-editor.org/rfc/rfc8446#page-27
	payload, err := s.tlsClientHelloPayload()
	if err != nil {
		return "", err
	}
	return extractSniFromTls(quicutils.BuiltinBytesLocator(payload))
}

func extractSniFromTls(search quicutils.Locator) (sni string, err error) {
	boundary := 39
	if search.Len() < boundary {
		return "", ErrNotApplicable
	}
	// Transport Layer Security (TLS) Extensions: Extension Definitions
	// https://www.rfc-editor.org/rfc/rfc6066#page-5
	b, err := search.Range(0, 6)
	if err != nil {
		return "", err
	}
	if b[0] != HandShakeType_Hello {
		return "", ErrNotApplicable
	}

	// Three bytes length.
	// length2 := (int(b[1]) << 16) + (int(b[2]) << 8) + int(b[3])

	if b[4] != 0x03 || b[5] < 0x01 || b[5] > 0x03 {
		return "", ErrNotApplicable
	}

	// Skip 32 bytes random.

	sessionIdLength, err := search.At(boundary - 1)
	if err != nil {
		return "", err
	}
	boundary += int(sessionIdLength) + 2 // +2 because the next field has 2B length
	if search.Len() < boundary {
		return "", ErrNotApplicable
	}

	b, err = search.Range(boundary-2, boundary)
	if err != nil {
		return "", err
	}
	cipherSuiteLength := int(binary.BigEndian.Uint16(b))
	boundary += cipherSuiteLength + 1 // +1 because the next field has 1B length
	if search.Len() < boundary {
		return "", ErrNotApplicable
	}

	compressMethodsLength, err := search.At(boundary - 1)
	if err != nil {
		return "", err
	}
	boundary += int(compressMethodsLength) + 2 // +2 because the next field has 2B length
	if search.Len() < boundary {
		return "", ErrNotApplicable
	}

	b, err = search.Range(boundary-2, boundary)
	if err != nil {
		return "", err
	}
	extensionsLength := int(binary.BigEndian.Uint16(b))
	boundary += extensionsLength + 0 // +0 because our search ends
	if search.Len() < boundary {
		return "", ErrNotApplicable
	}
	// Search SNI. Operate over the extensions region with absolute indices
	// instead of slicing the locator: slicing would box a new value into the
	// Locator interface on every call (BuiltinBytesLocator.Slice and
	// LinearLocator.Slice were a leading source of TLS/QUIC allocations).
	// base is the absolute offset where the extensions block starts and length
	// is its size; findSniExtension bounds iteration against length.
	base := boundary - extensionsLength
	return findSniExtension(search, base, extensionsLength)
}

func findSniExtension(search quicutils.Locator, base, length int) (d string, err error) {
	i := 0
	var b []byte
	for {
		if i+4 >= length {
			return "", ErrNotFound
		}
		b, err = search.Range(base+i, base+i+4)
		if err != nil {
			return "", err
		}
		typ := binary.BigEndian.Uint16(b)
		extLength := int(binary.BigEndian.Uint16(b[2:]))

		iNextField := i + 4 + extLength
		if iNextField > length {
			return "", ErrNotApplicable
		}
		if typ == TlsExtension_ServerName {
			b, err = search.Range(base+i+4, base+i+6)
			if err != nil {
				return "", err
			}
			sniLen := int(binary.BigEndian.Uint16(b))
			if extLength < sniLen+2 {
				return "", ErrNotApplicable
			}
			// Search HostName type SNI.
			for j, indicatorLen := i+6, 0; j+3 <= iNextField; j += 3 + indicatorLen {
				b, err = search.Range(base+j, base+j+3)
				if err != nil {
					return "", err
				}
				indicatorLen = int(binary.BigEndian.Uint16(b[1:]))
				if b[0] != TlsExtension_ServerNameType_HostName {
					continue
				}
				if j+3+indicatorLen > iNextField {
					return "", ErrNotApplicable
				}
				b, err = search.Range(base+j+3, base+j+3+indicatorLen)
				if err != nil {
					return "", err
				}
				// An SNI value may not include a trailing dot.
				// https://tools.ietf.org/html/rfc6066#section-3
				// But we accept it here.
				return strings.TrimSuffix(string(b), "."), nil
			}
		}
		i = iNextField
	}
}

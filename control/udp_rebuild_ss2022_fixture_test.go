// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol"
	ss "github.com/daeuniverse/outbound/protocol/shadowsocks"
	ss2022 "github.com/daeuniverse/outbound/protocol/shadowsocks_2022"
)

// ss2022RelayCodec is the server half of SIP022 UDP for the single-PSK
// AES-GCM ciphers. Each client socket is one client session; the relay keeps
// one server session per client session, as a real server does.
type ss2022RelayCodec struct {
	psk     []byte
	conf    *ciphers.CipherConf2022
	block   cipher.Block
	mu      sync.Mutex
	clients map[netip.AddrPort]*ss2022RelaySession
}

type ss2022RelaySession struct {
	client, server [8]byte
	packetID       uint64
}

const ss2022FixtureCipher = "2022-blake3-aes-256-gcm"

func newSS2022RelayCodec() (*ss2022RelayCodec, string, error) {
	conf := ciphers.Aead2022CiphersConf[ss2022FixtureCipher]
	psk := make([]byte, conf.KeyLen)
	if _, err := rand.Read(psk); err != nil {
		return nil, "", err
	}
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, "", err
	}
	return &ss2022RelayCodec{psk: psk, conf: conf, block: block, clients: make(map[netip.AddrPort]*ss2022RelaySession)}, base64.StdEncoding.EncodeToString(psk), nil
}

func (c *ss2022RelayCodec) decode(client netip.AddrPort, b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 16+c.conf.TagLen {
		return netip.AddrPort{}, nil, errors.New("short SS2022 packet")
	}
	var header [16]byte
	c.block.Decrypt(header[:], b[:16])
	aead, err := ss2022.CreateCipher(c.psk, header[:8], c.conf)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	plain, err := aead.Open(nil, header[4:16], b[16:], nil)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	if len(plain) < 11 || plain[0] != ss2022.HeaderTypeClientStream {
		return netip.AddrPort{}, nil, errors.New("bad SS2022 client header")
	}
	if d := time.Since(time.Unix(int64(binary.BigEndian.Uint64(plain[1:9])), 0)); d > 30*time.Second || d < -30*time.Second {
		return netip.AddrPort{}, nil, errors.New("SS2022 timestamp outside window")
	}
	body := plain[11+int(binary.BigEndian.Uint16(plain[9:11])):]
	n, err := ss.BytesSizeForMetadata(body)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	m, err := ss.NewMetadata(body)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	c.mu.Lock()
	s := c.clients[client]
	if s == nil {
		s = &ss2022RelaySession{}
		_, _ = rand.Read(s.server[:])
		c.clients[client] = s
	}
	copy(s.client[:], header[:8])
	c.mu.Unlock()
	return netip.AddrPortFrom(m.IP, m.Port), append([]byte(nil), body[n:]...), nil
}

func (c *ss2022RelayCodec) encode(client, peer netip.AddrPort, payload []byte) ([]byte, error) {
	c.mu.Lock()
	s := c.clients[client]
	if s == nil {
		c.mu.Unlock()
		return nil, errors.New("reply before SS2022 client session")
	}
	s.packetID++
	var header [16]byte
	copy(header[:8], s.server[:])
	binary.BigEndian.PutUint64(header[8:], s.packetID)
	clientSession := s.client
	c.mu.Unlock()
	m := ss.Metadata{Metadata: protocol.Metadata{Type: protocol.MetadataTypeIPv4, IP: peer.Addr(), Port: peer.Port()}}
	if peer.Addr().Is6() {
		m.Type = protocol.MetadataTypeIPv6
	}
	addr, err := m.Bytes()
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 0, 19+len(addr)+len(payload))
	plain = append(plain, ss2022.HeaderTypeServerStream)
	plain = binary.BigEndian.AppendUint64(plain, uint64(time.Now().Unix()))
	plain = append(plain, clientSession[:]...)
	plain = append(plain, 0, 0)
	plain = append(append(plain, addr...), payload...)
	aead, err := ss2022.CreateCipher(c.psk, header[:8], c.conf)
	if err != nil {
		return nil, err
	}
	wire := make([]byte, 16, 16+len(plain)+c.conf.TagLen)
	c.block.Encrypt(wire, header[:])
	return aead.Seal(wire, header[4:16], plain, nil), nil
}

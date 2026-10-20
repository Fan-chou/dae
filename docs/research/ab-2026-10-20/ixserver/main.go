// ixserver: loopback inner-traffic origin for the Vision A/B. HTTPS (TLS 1.3 or
// 1.2) or plain HTTP, plus a UDP echo. Deterministic payload so clients can
// verify bytes without shipping the file.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func stream(seed uint64, n int64, w io.Writer) {
	var ctr [16]byte
	binary.BigEndian.PutUint64(ctr[:8], seed)
	var i uint64
	for n > 0 {
		binary.BigEndian.PutUint64(ctr[8:], i)
		i++
		sum := sha256.Sum256(ctr[:])
		k := int64(len(sum))
		if k > n {
			k = n
		}
		w.Write(sum[:k])
		n -= k
	}
}

func selfSigned(dir string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	kb, _ := x509.MarshalECPrivateKey(k)
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kp := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	os.WriteFile(filepath.Join(dir, "cert.pem"), cp, 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), kp, 0o600)
	c, _ := tls.X509KeyPair(cp, kp)
	return c
}

func main() {
	mode := flag.String("mode", "tls13", "tls13|tls12|plain")
	addr := flag.String("addr", "127.0.0.1:18500", "listen")
	udp := flag.String("udp", "127.0.0.1:18501", "udp echo listen")
	dir := flag.String("dir", ".", "cert output dir")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/blob", func(w http.ResponseWriter, r *http.Request) {
		mb, _ := strconv.Atoi(r.URL.Query().Get("mb"))
		seed, _ := strconv.ParseUint(r.URL.Query().Get("seed"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(int64(mb)<<20, 10))
		stream(seed, int64(mb)<<20, w)
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		fmt.Fprintf(w, "%d %s", n, hex.EncodeToString(h.Sum(nil)))
	})
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pong") })
	pc, err := net.ListenPacket("udp", *udp)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		b := make([]byte, 65536)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	switch *mode {
	case "tls13", "tls12":
		cfg := &tls.Config{Certificates: []tls.Certificate{selfSigned(*dir)}}
		if *mode == "tls13" {
			cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		} else {
			cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		}
		ln = tls.NewListener(ln, cfg)
	}
	log.Printf("ixserver mode=%s tcp=%s udp=%s", *mode, *addr, *udp)
	log.Fatal(srv.Serve(ln))
}

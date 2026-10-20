package abtest

// Live A/B harness (not part of the repo's suite). It drives the dae-side
// client chain for one protocol ("AB_KIND") against an external server and
// carries inner HTTPS/UDP traffic served by ixserver. Each test prints
// "ABRES kind=... metric=... value=... unit=..." lines; scripts collect them.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/hysteria2"
	_ "github.com/daeuniverse/outbound/dialer/shadowsocks"
	_ "github.com/daeuniverse/outbound/dialer/socks"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vless"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks_2022"
	tls2 "github.com/daeuniverse/outbound/transport/tls"
)

const (
	abUUID  = "11111111-2222-4333-8444-555555555555"
	abSSKey = "AAECAwQFBgcICQoLDA0ODw==" // 16 bytes, 2022-blake3-aes-128-gcm
)

func env(t *testing.T, k string) string {
	v := os.Getenv(k)
	if v == "" {
		t.Skipf("%s unset", k)
	}
	return v
}

func kind() string { return os.Getenv("AB_KIND") }

func newDialer(t *testing.T) netproxy.Dialer {
	t.Helper()
	k := env(t, "AB_KIND")
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	if k == "direct" {
		return direct
	}
	port := env(t, "AB_PORT")
	addr := "127.0.0.1:" + port
	opt := &dialer.ExtraOption{AllowInsecure: true, TlsImplementation: "tls", UDPHopInterval: 30 * time.Second}
	var next netproxy.Dialer = direct
	if cp := os.Getenv("AB_CHAIN_PORT"); cp != "" {
		s, _, err := dialer.NewNetproxyDialerFromLink(direct, opt, "socks5://127.0.0.1:"+cp)
		if err != nil {
			t.Fatalf("socks chain: %v", err)
		}
		next = s
	}
	var link string
	switch k {
	case "vision", "vision-noflow":
		flow := vless.XRV
		if k == "vision-noflow" {
			flow = ""
		}
		td, _, err := tls2.NewTls(&dialer.ExtraOption{AllowInsecure: true, TlsImplementation: "tls"}, direct,
			"tls://"+addr+"?sni=127.0.0.1&allowInsecure=1")
		if err != nil {
			t.Fatal(err)
		}
		d, err := protocol.NewDialer("vless", td, protocol.Header{IsClient: true, ProxyAddress: addr, Password: abUUID, Feature1: flow})
		if err != nil {
			t.Fatal(err)
		}
		return d
	case "vmess":
		j, _ := json.Marshal(map[string]string{"v": "2", "ps": "ab", "add": "127.0.0.1", "port": port, "id": abUUID,
			"aid": "0", "net": "tcp", "type": "none", "host": "", "path": "", "tls": "", "scy": "auto"})
		link = "vmess://" + base64.StdEncoding.EncodeToString(j)
	case "ss2022":
		u := url.URL{Scheme: "ss", User: url.UserPassword("2022-blake3-aes-128-gcm", abSSKey), Host: addr}
		link = u.String()
	case "hy2":
		link = "hysteria2://abpass@" + addr + "?insecure=1&sni=127.0.0.1"
	case "hy2hop":
		link = "hysteria2://abpass@127.0.0.1:" + port + "-" + port + "?insecure=1&sni=127.0.0.1"
	case "reality":
		link = "vless://" + abUUID + "@" + addr + "?type=tcp&security=reality&flow=xtls-rprx-vision&sni=ab.example.test&fp=chrome&pbk=" +
			env(t, "AB_REALITY_PUB") + "&sid=" + env(t, "AB_REALITY_SID")
	default:
		t.Fatalf("unknown AB_KIND %q", k)
	}
	d, _, err := dialer.NewNetproxyDialerFromLink(next, opt, link)
	if err != nil {
		t.Fatalf("NewNetproxyDialerFromLink(%s): %v", k, err)
	}
	return d
}

func newClient(t *testing.T, keepAlive bool) (*http.Client, string) {
	d := newDialer(t)
	target := env(t, "AB_TARGET")
	inner := env(t, "AB_INNER")
	tr := &http.Transport{
		DisableKeepAlives:   !keepAlive,
		MaxIdleConnsPerHost: 64,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := d.DialContext(ctx, "tcp", target)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: c}, nil
		},
	}
	scheme := "http"
	if inner != "plain" {
		scheme = "https"
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1"}
		if inner == "tls13" {
			cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
		} else {
			cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		}
		tr.TLSClientConfig = cfg
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, scheme + "://" + target
}

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

func sumOf(seed uint64, n int64) string {
	h := sha256.New()
	stream(seed, n, h)
	return hex.EncodeToString(h.Sum(nil))
}

func res(metric string, v float64, unit string) {
	fmt.Printf("ABRES kind=%s metric=%s value=%.4f unit=%s\n", kind(), metric, v, unit)
}

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(float64(len(s)-1) * p)
	return s[i]
}

func cpuSeconds() float64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 + float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
}

// ---------------------------------------------------------------- correctness

func TestABDownload(t *testing.T) {
	c, base := newClient(t, true)
	ok, bad := 0, 0
	for i := 0; i < 4; i++ {
		seed := uint64(100 + i)
		resp, err := c.Get(fmt.Sprintf("%s/blob?mb=8&seed=%d", base, seed))
		if err != nil {
			bad++
			t.Logf("download %d: %v", i, err)
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, resp.Body)
		resp.Body.Close()
		if err != nil || n != 8<<20 || hex.EncodeToString(h.Sum(nil)) != sumOf(seed, 8<<20) {
			bad++
			t.Logf("download %d: n=%d err=%v", i, n, err)
			continue
		}
		ok++
	}
	fmt.Printf("ABCHK kind=%s case=download ok=%d fail=%d\n", kind(), ok, bad)
	if bad > 0 {
		t.Fail()
	}
}

func TestABUpload(t *testing.T) {
	c, base := newClient(t, true)
	var buf bytes.Buffer
	stream(777, 4<<20, &buf)
	resp, err := c.Post(base+"/up", "application/octet-stream", &buf)
	if err != nil {
		fmt.Printf("ABCHK kind=%s case=upload ok=0 fail=1\n", kind())
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	good := string(b) == fmt.Sprintf("%d %s", 4<<20, sumOf(777, 4<<20))
	o, f := 0, 1
	if good {
		o, f = 1, 0
	}
	fmt.Printf("ABCHK kind=%s case=upload ok=%d fail=%d\n", kind(), o, f)
	if !good {
		t.Fatalf("upload mismatch: %s", b)
	}
}

func TestABManyConns(t *testing.T) {
	c, base := newClient(t, false)
	var mu sync.Mutex
	ok, bad := 0, 0
	run := func(n int) {
		for i := 0; i < n; i++ {
			resp, err := c.Get(base + "/ping")
			good := false
			if err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				good = string(b) == "pong"
			}
			mu.Lock()
			if good {
				ok++
			} else {
				bad++
				if err != nil && bad <= 3 {
					t.Logf("fail sample: %v", err)
				}
			}
			mu.Unlock()
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() { defer wg.Done(); run(15) }()
	}
	run(50)
	wg.Wait()
	fmt.Printf("ABCHK kind=%s case=manyconns ok=%d fail=%d\n", kind(), ok, bad)
	if bad > 0 {
		t.Fail()
	}
}

func udpConn(t *testing.T) netproxy.Conn {
	d := newDialer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "udp", env(t, "AB_UDP"))
	if err != nil {
		fmt.Printf("ABCHK kind=%s case=udp ok=0 fail=1\n", kind())
		t.Fatalf("udp dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestABUDP(t *testing.T) {
	c := udpConn(t)
	ok, bad := 0, 0
	for i, size := range []int{12, 64, 512, 1200, 1400, 4000, 1200, 64, 512, 12} {
		msg := bytes.Repeat([]byte{byte(i + 1)}, size)
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(msg); err != nil {
			bad++
			t.Logf("udp write size=%d: %v", size, err)
			continue
		}
		rb := make([]byte, 65536)
		n, err := c.Read(rb)
		if err != nil || !bytes.Equal(rb[:n], msg) {
			bad++
			t.Logf("udp size=%d: n=%d err=%v", size, n, err)
			continue
		}
		ok++
	}
	fmt.Printf("ABCHK kind=%s case=udp ok=%d fail=%d\n", kind(), ok, bad)
	if bad > 0 {
		t.Fail()
	}
}

// ---------------------------------------------------------------- performance

func TestABPerfTput1(t *testing.T) {
	c, base := newClient(t, true)
	// warm the tunnel
	if resp, err := c.Get(base + "/blob?mb=4&seed=1"); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	cpu0, t0 := cpuSeconds(), time.Now()
	resp, err := c.Get(base + "/blob?mb=256&seed=2")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != 256<<20 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	el := time.Since(t0).Seconds()
	res("tput1_down", float64(n)/1e6/el, "MB/s")
	res("tput1_down_cpu", (cpuSeconds()-cpu0)/(float64(n)/1e9), "cpu_s/GB")
}

func TestABPerfUp1(t *testing.T) {
	c, base := newClient(t, true)
	var buf bytes.Buffer
	stream(5, 128<<20, &buf)
	cpu0, t0 := cpuSeconds(), time.Now()
	resp, err := c.Post(base+"/up", "application/octet-stream", &buf)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	el := time.Since(t0).Seconds()
	res("up1", 128*1.048576/el, "MB/s")
	res("up1_cpu", (cpuSeconds()-cpu0)/(128*1.048576/1000), "cpu_s/GB")
}

func TestABPerfTput8(t *testing.T) {
	c, base := newClient(t, true)
	cpu0, t0 := cpuSeconds(), time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := c.Get(fmt.Sprintf("%s/blob?mb=64&seed=%d", base, 10+i))
			if err != nil {
				t.Errorf("stream %d: %v", i, err)
				return
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			mu.Lock()
			total += n
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	el := time.Since(t0).Seconds()
	res("tput8_down", float64(total)/1e6/el, "MB/s")
	res("tput8_down_cpu", (cpuSeconds()-cpu0)/(float64(total)/1e9), "cpu_s/GB")
}

func TestABPerfTTFB(t *testing.T) {
	d := newDialer(t)
	target := env(t, "AB_TARGET")
	inner := env(t, "AB_INNER")
	var dialMs, totMs []float64
	fails := 0
	for i := 0; i < 300; i++ {
		t0 := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			cancel()
			fails++
			continue
		}
		dialMs = append(dialMs, float64(time.Since(t0).Microseconds())/1000)
		var nc net.Conn = &netproxy.FakeNetConn{Conn: c}
		if inner != "plain" {
			cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1"}
			if inner == "tls13" {
				cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
			} else {
				cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			}
			tc := tls.Client(nc, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				cancel()
				_ = c.Close()
				fails++
				continue
			}
			nc = tc
		}
		_ = nc.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := nc.Write([]byte("GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
			cancel()
			_ = c.Close()
			fails++
			continue
		}
		one := make([]byte, 1)
		if _, err := io.ReadFull(nc, one); err != nil {
			cancel()
			_ = c.Close()
			fails++
			continue
		}
		totMs = append(totMs, float64(time.Since(t0).Microseconds())/1000)
		cancel()
		_ = c.Close()
	}
	res("ttfb_dial_p50", pct(dialMs, .5), "ms")
	res("ttfb_dial_p99", pct(dialMs, .99), "ms")
	res("ttfb_total_p50", pct(totMs, .5), "ms")
	res("ttfb_total_p99", pct(totMs, .99), "ms")
	res("ttfb_fail", float64(fails), "count")
}

func TestABPerfRTT(t *testing.T) {
	c, base := newClient(t, true)
	get := func() {
		resp, err := c.Get(base + "/ping")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	for i := 0; i < 200; i++ {
		get()
	}
	var ms []float64
	for i := 0; i < 3000; i++ {
		t0 := time.Now()
		get()
		ms = append(ms, float64(time.Since(t0).Microseconds())/1000)
	}
	res("rtt_p50", pct(ms, .5), "ms")
	res("rtt_p99", pct(ms, .99), "ms")
	res("rtt_max", pct(ms, 1), "ms")
}

func TestABPerfUDP(t *testing.T) {
	c := udpConn(t)
	rb := make([]byte, 65536)
	for _, size := range []int{64, 1200} {
		msg := bytes.Repeat([]byte{7}, size)
		var ms []float64
		lost := 0
		for i := 0; i < 2000; i++ {
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			t0 := time.Now()
			if _, err := c.Write(msg); err != nil {
				lost++
				continue
			}
			if _, err := c.Read(rb); err != nil {
				lost++
				continue
			}
			ms = append(ms, float64(time.Since(t0).Microseconds())/1000)
		}
		res(fmt.Sprintf("udp%d_rtt_p50", size), pct(ms, .5), "ms")
		res(fmt.Sprintf("udp%d_rtt_p99", size), pct(ms, .99), "ms")
		res(fmt.Sprintf("udp%d_lost", size), float64(lost), "count")
	}
	// burst: sender floods, reader counts what comes back
	msg := bytes.Repeat([]byte{9}, 512)
	const total = 20000
	var got int
	done := make(chan struct{})
	_ = c.SetDeadline(time.Time{})
	go func() {
		defer close(done)
		for {
			_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			if _, err := c.Read(rb); err != nil {
				return
			}
			got++
		}
	}()
	t0 := time.Now()
	for i := 0; i < total; i++ {
		if _, err := c.Write(msg); err != nil {
			break
		}
	}
	sendEl := time.Since(t0).Seconds()
	<-done
	res("udp_burst_send_pps", total/sendEl, "pps")
	res("udp_burst_recv_ratio", float64(got)/total, "ratio")
}

//go:build linux

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	"golang.org/x/sys/unix"
)

// Opt-in kernel lab. All MTU/sysctl changes occur in child network namespaces,
// never the host namespace. Relay modes exercise the production copy engines;
// they are not an encrypted proxy or a WAN throughput benchmark.
func TestTCPMSSMatrixLive(t *testing.T) {
	if os.Getenv("DAE_TEST_TCP_MSS_MATRIX") != "1" {
		t.Skip("set DAE_TEST_TCP_MSS_MATRIX=1 for the isolated kernel matrix")
	}
	if os.Getenv("DAE_TEST_TCP_MSS_MATRIX_CHILD") == "1" {
		mssMatrixChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("matrix requires root and private network namespaces")
	}
	parentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	for _, mtu := range []int{1280, 1500} {
		for _, timestamps := range []int{0, 1} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestTCPMSSMatrixLive$", "-test.v")
			cmd.Env = append(os.Environ(), "DAE_TEST_TCP_MSS_MATRIX_CHILD=1", "DAE_TEST_TCP_MSS_PARENT_NS="+parentNS,
				fmt.Sprintf("DAE_TEST_TCP_MSS_MTU=%d", mtu), fmt.Sprintf("DAE_TEST_TCP_MSS_TIMESTAMPS=%d", timestamps))
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("MTU %d timestamps %d: %v\n%s", mtu, timestamps, err, out)
			}
			t.Logf("MTU %d timestamps %d:\n%s", mtu, timestamps, out)
		}
	}
}

func mssMatrixChild(t *testing.T) {
	currentNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parentNS := os.Getenv("DAE_TEST_TCP_MSS_PARENT_NS")
	actualParentNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", os.Getppid()))
	if err != nil {
		t.Fatalf("verify parent network namespace: %v", err)
	}
	if parentNS == "" || actualParentNS != parentNS || currentNS == actualParentNS {
		t.Fatal("refusing to change MTU/sysctl outside a verified child network namespace")
	}
	mtu, err := strconv.Atoi(os.Getenv("DAE_TEST_TCP_MSS_MTU"))
	if err != nil || (mtu != 1280 && mtu != 1500) {
		t.Fatal("invalid matrix MTU")
	}
	ts, err := strconv.Atoi(os.Getenv("DAE_TEST_TCP_MSS_TIMESTAMPS"))
	if err != nil || (ts != 0 && ts != 1) {
		t.Fatal("invalid matrix timestamps")
	}
	for _, command := range [][]string{
		{"ip", "link", "set", "lo", "mtu", strconv.Itoa(mtu), "up"},
		{"sysctl", "-qw", "net.ipv4.tcp_timestamps=" + strconv.Itoa(ts)},
	} {
		if out, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", command[0], err, out)
		}
	}
	payload := bytes.Repeat([]byte("tcp-mss-lab-0123"), 1<<20) // 16 MiB
	wantCRC := crc32.ChecksumIEEE(payload)
	type settings struct{ dial, listen int }
	cases := []settings{{0, 0}, {1380, 0}, {0, 1380}, {1380, 1380}}
	for round := 0; round < 3; round++ {
		for _, network := range []string{"tcp4", "tcp6"} {
			for _, mode := range []string{"direct", "relay_splice", "relay_buffered"} {
				for i := range cases {
					index := i
					if round%2 == 1 {
						index = len(cases) - 1 - i
					}
					cfg := cases[index]
					mssMatrixTransfer(t, network, mode, mtu, ts, cfg.dial, cfg.listen, round, payload, wantCRC)
				}
			}
		}
	}
}

func mssMatrixTCPInfo(t *testing.T, conn *net.TCPConn) *unix.TCPInfo {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var info *unix.TCPInfo
	var optErr error
	if err := raw.Control(func(fd uintptr) { info, optErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil {
		t.Fatal(err)
	}
	if optErr != nil {
		t.Fatal(optErr)
	}
	return info
}

type mssMatrixCopyResult struct {
	bytes, accounted int64
	err              error
}

func mssMatrixTransfer(t *testing.T, network, mode string, mtu, timestamps, dialMSS, listenMSS, round int, payload []byte, wantCRC uint32) {
	t.Helper()
	bind := "127.0.0.1:0"
	if network == "tcp6" {
		bind = "[::1]:0"
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return tcpIngressListenControl(raw, listenMSS) }}
	ingress, err := lc.Listen(context.Background(), network, bind)
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	pair := direct.NewDirectDialersWithOption(direct.Option{TCPMaxSeg: dialMSS})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	magic := netproxy.MagicNetwork{Network: "tcp", IPVersion: network[3:]}.Encode()
	var client *net.TCPConn
	if mode == "direct" {
		conn, err := pair.Symmetric.DialContext(ctx, magic, ingress.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		client = conn.(*net.TCPConn)
	} else {
		conn, err := net.DialTimeout(network, ingress.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		client = conn.(*net.TCPConn)
	}
	defer client.Close()
	accepted, err := ingress.Accept()
	if err != nil {
		t.Fatal(err)
	}
	inbound := accepted.(*net.TCPConn)
	defer inbound.Close()
	server, sender := inbound, client
	var forward, reverse chan mssMatrixCopyResult
	if mode != "direct" {
		target, err := net.Listen(network, bind)
		if err != nil {
			t.Fatal(err)
		}
		defer target.Close()
		conn, err := pair.Symmetric.DialContext(ctx, magic, target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		underlay := conn.(*net.TCPConn)
		defer underlay.Close()
		accepted, err := target.Accept()
		if err != nil {
			t.Fatal(err)
		}
		server, sender = accepted.(*net.TCPConn), underlay
		defer server.Close()
		forward, reverse = make(chan mssMatrixCopyResult, 1), make(chan mssMatrixCopyResult, 1)
		copyLeg := func(dst, src *net.TCPConn, done chan mssMatrixCopyResult) {
			var accounted int64
			record := func(n int64) { accounted += n }
			var n int64
			var err error
			if mode == "relay_splice" {
				n, err = (defaultRelayCopyEngine{}).Copy(ctx, dst, src, record, nil)
			} else {
				n, err = relayCopyLoop(ctx, dst, src, make([]byte, relayCopyBufferSize), record, nil)
			}
			_ = dst.CloseWrite()
			done <- mssMatrixCopyResult{n, accounted, err}
		}
		go copyLeg(underlay, inbound, forward)
		go copyLeg(inbound, underlay, reverse)
	}
	for _, conn := range []*net.TCPConn{client, inbound, server, sender} {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	before := mssMatrixTCPInfo(t, sender)
	clientInfo := mssMatrixTCPInfo(t, client)
	mtuMSS := mtu - 40
	if network == "tcp6" {
		mtuMSS = mtu - 60
	}
	for _, info := range []*unix.TCPInfo{before, clientInfo} {
		if info.Snd_mss == 0 || int(info.Snd_mss) > mtuMSS {
			t.Fatalf("MSS %d exceeds MTU bound %d", info.Snd_mss, mtuMSS)
		}
		// Linux UAPI TCPI_OPT_TIMESTAMPS = 1; the pinned x/sys omits it.
		if (info.Options&1 != 0) != (timestamps == 1) {
			t.Fatalf("timestamp options = %#x, wanted %d", info.Options, timestamps)
		}
	}
	if dialMSS != 0 && int(before.Snd_mss) > dialMSS {
		t.Fatalf("dial MSS %d exceeds %d", before.Snd_mss, dialMSS)
	}
	if listenMSS != 0 && int(clientInfo.Snd_mss) > listenMSS {
		t.Fatalf("listen MSS %d exceeds %d", clientInfo.Snd_mss, listenMSS)
	}
	const pings = 16
	serverDone := make(chan error, 1)
	go func() {
		var b [1]byte
		for i := 0; i < pings; i++ {
			if _, err := io.ReadFull(server, b[:]); err != nil {
				serverDone <- err
				return
			}
			if _, err := server.Write(b[:]); err != nil {
				serverDone <- err
				return
			}
		}
		h := crc32.NewIEEE()
		if _, err := io.CopyN(h, server, int64(len(payload))); err != nil {
			serverDone <- err
			return
		}
		if h.Sum32() != wantCRC {
			serverDone <- fmt.Errorf("payload CRC mismatch")
			return
		}
		_, err := server.Write([]byte{0x7b})
		if err == nil {
			err = server.CloseWrite()
		}
		serverDone <- err
	}()
	rtts := make([]int64, pings)
	var ping [1]byte
	for i := range rtts {
		start := time.Now()
		if _, err := client.Write(ping[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, ping[:]); err != nil {
			t.Fatal(err)
		}
		rtts[i] = time.Since(start).Nanoseconds()
	}
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	start := time.Now()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(client, ack[:]); err != nil || ack[0] != 0x7b {
		t.Fatalf("payload acknowledgement: %x, %v", ack, err)
	}
	elapsed := time.Since(start)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if mode != "direct" {
		for _, leg := range []struct {
			done chan mssMatrixCopyResult
			want int64
		}{{forward, int64(len(payload) + pings)}, {reverse, pings + 1}} {
			result := <-leg.done
			if result.err != nil || result.bytes != leg.want || result.accounted != leg.want {
				t.Fatalf("relay/accounting: %+v, want %d", result, leg.want)
			}
		}
	}
	after := mssMatrixTCPInfo(t, sender)
	clientAfter := mssMatrixTCPInfo(t, client)
	row := map[string]any{
		"network": network, "mode": mode, "mtu": mtu, "timestamps": timestamps, "dial_mss": dialMSS, "listen_mss": listenMSS, "round": round,
		"sender_mss": before.Snd_mss, "ingress_mss": clientInfo.Snd_mss, "bytes": len(payload), "elapsed_ns": elapsed.Nanoseconds(),
		"mbps": float64(len(payload)) * 8 / elapsed.Seconds() / 1e6, "ping_p50_ns": rtts[len(rtts)/2], "ping_p95_ns": rtts[len(rtts)-1],
		"sender_rtt_us": after.Rtt, "sender_retransmits": after.Total_retrans - before.Total_retrans,
		"client_retransmits": clientAfter.Total_retrans - clientInfo.Total_retrans,
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("MSS_MATRIX %s", b)
}

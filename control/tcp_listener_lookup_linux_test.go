//go:build linux && !dae_stub_ebpf

package control

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"golang.org/x/sys/unix"
)

// Run in a child netns so the lookup hook cannot affect the test runner's
// sockets. A server-active close leaves TIME_WAIT at the redirected tuple;
// immediately reconnecting that tuple must still reach the listener.
func TestTCPListenerLookupTupleReuse(t *testing.T) {
	if os.Getenv("DAE_TEST_TCP_LOOKUP_CHILD") != "1" {
		if os.Geteuid() != 0 {
			t.Skip("requires root and a private network namespace")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestTCPListenerLookupTupleReuse$", "-test.v")
		cmd.Env = append(os.Environ(), "DAE_TEST_TCP_LOOKUP_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated TCP lookup: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable loopback: %v: %s", err, out)
	}
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "tproxy_tcp_listener" {
			delete(spec.Programs, name)
		}
	}
	for name, m := range spec.Maps {
		if name != "listen_socket_map" && name != "conn_state_map" && name[0] != '.' {
			delete(spec.Maps, name)
			continue
		}
		m.Pinning = ebpf.PinNone
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	l, err := link.AttachNetNs(int(ns.Fd()), coll.Programs["tproxy_tcp_listener"])
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Attach a second populated generation before changing TC's owner.
	nextSpec := spec.Copy()
	if err := nextSpec.Variables["PARAM"].Set(bpfDaeParam{DatapathGeneration: 1}); err != nil {
		t.Fatal(err)
	}
	next, err := ebpf.NewCollectionWithOptions(nextSpec, ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"conn_state_map": coll.Maps["conn_state_map"]}})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	nextLink, err := link.AttachNetNs(int(ns.Fd()), next.Programs["tproxy_tcp_listener"])
	if err != nil {
		t.Fatal(err)
	}
	defer nextLink.Close()
	for _, tc := range []struct {
		network, bind, target, source string
		key                           uint32
	}{
		{"tcp4", "0.0.0.0:0", "127.0.0.2:42424", "127.0.0.1", 0},
		{"tcp6", "[::]:0", "[::1]:42424", "::1", 2},
	} {
		t.Run(tc.network, func(t *testing.T) {
			lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
				return dialer.TproxyControl(raw)
			}}
			listener, err := lc.Listen(context.Background(), tc.network, tc.bind)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			file, err := dupTCPListenerFile(listener)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := coll.Maps["listen_socket_map"].Update(tc.key, uint64(file.Fd()), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			nextListener, err := lc.Listen(context.Background(), tc.network, tc.bind)
			if err != nil {
				t.Fatal(err)
			}
			defer nextListener.Close()
			nextFile, err := dupTCPListenerFile(nextListener)
			if err != nil {
				t.Fatal(err)
			}
			defer nextFile.Close()
			if err := next.Maps["listen_socket_map"].Update(tc.key, uint64(nextFile.Fd()), ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			nextDone := make(chan struct{})
			go func() {
				defer close(nextDone)
				for {
					conn, err := nextListener.Accept()
					if err != nil {
						return
					}
					conn.Write([]byte("next"))
					conn.Close()
				}
			}()
			errs := make(chan error, 1)
			go func() {
				for {
					c, err := listener.Accept()
					if err != nil {
						errs <- err
						return
					}
					_, err = c.Write([]byte("ok"))
					c.Close() // server sends FIN first
					if err != nil {
						errs <- err
						return
					}
				}
			}()
			d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(tc.source), Port: 41001}, Control: func(_, _ string, raw syscall.RawConn) error {
				var sockErr error
				err := raw.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) })
				if err != nil {
					return err
				}
				return sockErr
			}}
			tuple := bpfTuplesKeyFromAddrPorts(netip.AddrPortFrom(netip.MustParseAddr(tc.source), 41001), netip.MustParseAddrPort(tc.target), unix.IPPROTO_TCP)
			if err := coll.Maps["conn_state_map"].Update(tuple, bpfConnState{}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 10; i++ {
				// old -> new -> old covers pre-commit, commit and rollback,
				// with both lookup links and listener maps populated throughout.
				owner := uint16(0)
				want := "ok"
				if i >= 3 && i < 7 {
					owner = 1
					want = "next"
				}
				if err := coll.Maps["conn_state_map"].Update(tuple, bpfConnState{DatapathGeneration: owner}, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				c, err := d.Dial(tc.network, tc.target)
				if err != nil {
					t.Fatalf("reuse %d: %v", i, err)
				}
				c.SetDeadline(time.Now().Add(time.Second))
				data, err := io.ReadAll(c)
				c.Close()
				if err != nil || string(data) != want {
					t.Fatalf("reuse %d: %q: %v", i, data, err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			nextListener.Close()
			<-nextDone
			listener.Close()
			select {
			case <-errs:
			case <-time.After(time.Second):
				t.Fatal("accept loop did not exit")
			}
		})
	}
}

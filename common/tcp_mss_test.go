package common

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestParseTCPMSS(t *testing.T) {
	for _, tc := range []struct {
		name, dial, listen, errField string
		want                         TCPMSSOptions
	}{
		{name: "default"},
		{name: "zero", dial: "0", listen: "0"},
		{name: "separate", dial: "1380", listen: "1200", want: TCPMSSOptions{1380, 1200}},
		{name: "min", dial: "88", want: TCPMSSOptions{Dial: 88}},
		{name: "max", listen: "32767", want: TCPMSSOptions{Listen: 32767}},
		{name: "negative", dial: "-1", errField: "DAE_TCP_DIAL_MSS"},
		{name: "too small", listen: "87", errField: "DAE_TCP_LISTEN_MSS"},
		{name: "too large", dial: "32768", errField: "DAE_TCP_DIAL_MSS"},
		{name: "invalid", listen: "1380garbage", errField: "DAE_TCP_LISTEN_MSS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTCPMSS(func(name string) string {
				if name == "DAE_TCP_DIAL_MSS" {
					return tc.dial
				}
				return tc.listen
			})
			if tc.errField != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errField) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if !netproxy.TCPMaxSegSupported && tc.want != (TCPMSSOptions{}) {
				if err == nil {
					t.Fatal("explicit MSS must fail on unsupported platform")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestProcessTCPMSSSurvivesReload(t *testing.T) {
	if os.Getenv("DAE_TEST_TCP_MSS_CHILD") == "1" {
		first, err := ProcessTCPMSS()
		if err != nil || first != (TCPMSSOptions{}) {
			t.Fatalf("first = %+v, %v", first, err)
		}
		t.Setenv("DAE_TCP_DIAL_MSS", "1380")
		t.Setenv("DAE_TCP_LISTEN_MSS", "1200")
		next, err := ProcessTCPMSS()
		if err != nil || next != first {
			t.Fatalf("reload changed process options: %+v, %v", next, err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessTCPMSSSurvivesReload$")
	cmd.Env = append(os.Environ(), "DAE_TEST_TCP_MSS_CHILD=1", "DAE_TCP_DIAL_MSS=0", "DAE_TCP_LISTEN_MSS=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

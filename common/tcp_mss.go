package common

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

// TCPMSSOptions holds process-scoped experiments. Changing them requires a
// restart because listener clones share their kernel socket across reloads.
type TCPMSSOptions struct {
	Dial   int
	Listen int
}

var processTCPMSS = sync.OnceValues(func() (TCPMSSOptions, error) {
	return parseTCPMSS(os.Getenv)
})

// ProcessTCPMSS returns the same options (or validation error) for every
// generation. Both experiments default to zero, preserving kernel defaults.
func ProcessTCPMSS() (TCPMSSOptions, error) { return processTCPMSS() }

func parseTCPMSS(getenv func(string) string) (TCPMSSOptions, error) {
	var options TCPMSSOptions
	for _, entry := range []struct {
		name string
		dst  *int
	}{
		{"DAE_TCP_DIAL_MSS", &options.Dial},
		{"DAE_TCP_LISTEN_MSS", &options.Listen},
	} {
		raw := getenv(entry.name)
		if raw == "" {
			continue
		}
		value, err := strconv.Atoi(raw)
		if err != nil {
			return TCPMSSOptions{}, fmt.Errorf("%s must be an integer: %w", entry.name, err)
		}
		if err := netproxy.ValidateTCPMaxSeg(value); err != nil {
			return TCPMSSOptions{}, fmt.Errorf("%s: %w", entry.name, err)
		}
		*entry.dst = value
	}
	return options, nil
}

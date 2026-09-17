package control

import (
	"fmt"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

func TestUDPDomainFailureDoesNotRetireAssociation(t *testing.T) {
	ue := &UdpEndpoint{}
	retired := false
	retire := func() { retired = true }
	for i := 0; i < 5; i++ {
		if ue.applyUpstreamReadErrorPolicy(fmt.Errorf("bad peer: %w", protocol.ErrDomainResolution), retire) || retired {
			t.Fatal("a framed domain failure retired the shared association")
		}
	}
	if !ue.applyUpstreamReadErrorPolicy(io.ErrUnexpectedEOF, retire) || !retired {
		t.Fatal("a broken stream must still retire")
	}
}

package mihomo

import (
	"context"
	"io"

	_ "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

// daeLinkValidator parses a link with dae's real dialer registry, the same
// path the control plane uses for node links.
func daeLinkValidator(link string) error {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	option := &dialer.GlobalOption{
		ExtraOption: D.ExtraOption{TlsImplementation: "tls", UtlsImitate: "chrome_auto"},
		Log:         logger,
	}
	d, err := dialer.NewFromLinkContext(context.Background(), option, dialer.InstanceOption{DisableCheck: true}, link, "")
	if err != nil {
		return err
	}
	if d == nil {
		return nil
	}
	return d.Close()
}

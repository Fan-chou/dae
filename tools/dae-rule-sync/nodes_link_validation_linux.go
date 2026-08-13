//go:build linux

package main

import (
	"io"

	_ "github.com/daeuniverse/dae/component/outbound"
	daeDialer "github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func validateMihomoLinkWithDae(link string) error {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.PanicLevel)
	option := &daeDialer.GlobalOption{
		ExtraOption: D.ExtraOption{TlsImplementation: "tls", UtlsImitate: "chrome_auto"},
		Log:         logger,
	}
	d, err := daeDialer.NewFromLink(option, daeDialer.InstanceOption{DisableCheck: true}, link, "")
	if err != nil {
		return err
	}
	if d == nil {
		return nil
	}
	return d.Close()
}

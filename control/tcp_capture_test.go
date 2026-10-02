// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"github.com/daeuniverse/dae/component/observation"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	"testing"
)

func TestCaptureIndependentFromQuality(t *testing.T) {
	options := localQualityOptions(config.Group{QualityMode: "off"}, nil)
	if options.Mode != "" || options.Report != nil {
		t.Fatal("capture must not enable quality")
	}
	c := &ControlPlane{}
	if c.startCapture(nil, "example.test") != nil || c.AdminCapture(0).Enabled {
		t.Fatal("default capture enabled")
	}
	collector, err := observation.New(1000)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	c.capture = collector
	c.captureGroup = "allowed"
	if c.startCapture(&proxyDialResult{Outbound: &outbound.DialerGroup{Name: "other"}}, "example.test") != nil {
		t.Fatal("group filter ignored")
	}
	f := c.startCapture(&proxyDialResult{Outbound: &outbound.DialerGroup{Name: "allowed"}}, "example.test")
	if f == nil {
		t.Fatal("quality off prevented capture")
	}
	runtime := &FlowRuntime{}
	runtime.capture.Store(f)
	// Existing accounting callback accepts a nil dialer and remains independent
	// from all quality state. Both directions are observed without relay wrapping.
	runtime.recordUpload(11)
	runtime.recordDownload(22)
	f.Finish("canceled")
	if runtime.uploadBytes.Load() != 11 || runtime.downloadBytes.Load() != 22 {
		t.Fatal("capture changed normal accounting")
	}
}

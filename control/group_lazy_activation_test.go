package control

import (
	"reflect"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	componentdialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/sirupsen/logrus"
)

func TestControlPlaneActivateCheckDefersLazyGroupUntilSelection(t *testing.T) {
	logger := logrus.New()
	option := &componentdialer.GlobalOption{
		Log:               logger,
		TcpCheckOptionRaw: componentdialer.TcpCheckOptionRaw{Raw: []string{"https://example.com/check"}},
		CheckDnsOptionRaw: componentdialer.CheckDnsOptionRaw{Raw: []string{"example.com:53"}},
		CheckInterval:     15 * time.Second,
	}
	underlay, property := componentdialer.NewDirectDialer(option, true)
	d := componentdialer.NewDialer(underlay, option, componentdialer.InstanceOption{}, property)
	group := outbound.NewDialerGroupWithRuntimeOptions(
		option,
		"lazy",
		[]*componentdialer.Dialer{d},
		[]*componentdialer.Annotation{{}},
		outbound.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed, FixedIndex: 0},
		func(bool, *componentdialer.NetworkType, bool) {},
		outbound.DialerGroupRuntimeOptions{HealthCheckEnabled: true, Lazy: true},
	)
	defer group.Close()
	defer d.Close()

	plane := &ControlPlane{
		log: logger,
		controlPlaneGenerationState: controlPlaneGenerationState{
			outbounds:           []*outbound.DialerGroup{group},
			referencedOutbounds: map[string]struct{}{"lazy": {}},
		},
	}
	plane.ActivateCheck()
	activated := func() bool {
		return reflect.ValueOf(d).Elem().FieldByName("checkActivated").Bool()
	}
	if activated() {
		t.Fatal("ControlPlane.ActivateCheck eagerly activated lazy group")
	}
	if _, _, err := group.Select(&componentdialer.NetworkType{
		L4Proto:   consts.L4ProtoStr_TCP,
		IpVersion: consts.IpVersionStr_4,
	}, true); err != nil {
		t.Fatalf("group.Select() error = %v", err)
	}
	if !activated() {
		t.Fatal("first group selection did not activate lazy health check")
	}
}

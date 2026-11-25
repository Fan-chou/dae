package cmd

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
)

// newTestRuntimeGeneration returns a minimal runtimeGeneration for runtime
// supervisor tests.
func newTestRuntimeGeneration() *runtimeGeneration {
	return &runtimeGeneration{
		controlPlane: &control.ControlPlane{},
		listener:     &control.Listener{},
		cancel:       func() {},
		conf:         &config.Config{},
	}
}

package control

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDeleteNamedNetnsReportsCleanupStages(t *testing.T) {
	originalUnmount, originalRemove := unmountNamedNetnsFunc, removeNamedNetnsFunc
	t.Cleanup(func() { unmountNamedNetnsFunc = originalUnmount; removeNamedNetnsFunc = originalRemove })
	for _, tc := range []struct {
		name               string
		sync, lazy, remove error
		wantError          bool
	}{
		{"missing", unix.ENOENT, unix.ENOENT, os.ErrNotExist, false},
		{"plain file", unix.EINVAL, unix.EINVAL, nil, false},
		{"lazy succeeds", unix.EBUSY, nil, nil, false},
		{"kernel locked", unix.EPERM, unix.EPERM, unix.EBUSY, true},
		{"remove denied", nil, nil, unix.EACCES, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var flags []int
			unmountNamedNetnsFunc = func(_ string, flag int) error {
				flags = append(flags, flag)
				if flag == 0 {
					return tc.sync
				}
				return tc.lazy
			}
			removeNamedNetnsFunc = func(string) error { return tc.remove }
			err := DeleteNamedNetns(NsName)
			if (err != nil) != tc.wantError {
				t.Fatalf("cleanup=%v", err)
			}
			if len(flags) == 0 || flags[0] != 0 || tc.sync != nil && (len(flags) != 2 || flags[1] != unix.MNT_DETACH) {
				t.Fatalf("unmount order: %v", flags)
			}
			if tc.wantError && !errors.Is(err, tc.remove) {
				t.Fatalf("lost remove errno: %v", err)
			}
		})
	}
}

func TestNetnsSetupStopsAtStaleCleanupFailure(t *testing.T) {
	original := deleteNamedNetnsFunc
	t.Cleanup(func() { deleteNamedNetnsFunc = original })
	deleteNamedNetnsFunc = func(string) error { return unix.EPERM }
	ns := &DaeNetns{}
	if err := ns.setupNetns(); !errors.Is(err, unix.EPERM) {
		t.Fatalf("setup=%v", err)
	}
	for _, name := range []string{"", ".", "..", "../../other"} {
		if err := DeleteNamedNetns(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

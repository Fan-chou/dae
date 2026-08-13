/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	groupSelectionStateVersion = 1
	groupSelectionStateDir     = "group-selections"
	groupSelectionStateName    = "state.json"
	groupSelectionLockName     = ".lock"
	groupSelectionFileMode     = 0o600
	groupSelectionDirMode      = 0o700
	groupSelectionMaxEntries   = 4096
	groupSelectionMaxTokenSize = 256
)

// GroupSelectionStateRelativePath is the path, relative to the dae config
// directory, used by the default store. The file contains member identities
// only; it must never contain links or credentials.
const GroupSelectionStateRelativePath = "persist.d/" + groupSelectionStateDir + "/" + groupSelectionStateName

type groupSelectionStateFile struct {
	Version    int               `json:"version"`
	Selections map[string]string `json:"selections"`
}

// GroupSelectionApplyResult describes how a persisted selection was applied.
// Index is -1 when the group has no current members.
type GroupSelectionApplyResult struct {
	GroupName       string
	RequestedMember string
	SelectedMember  string
	Index           int
	UsedFallback    bool
	Warning         string
}

// GroupSelectionStore persists Mihomo select choices by logical group/member
// identity. It deliberately accepts only dae-safe identifiers, which keeps
// links, passwords, tokens, and other endpoint material out of this state.
// The store is safe for concurrent use within a process and uses an advisory
// file lock for cross-process writers.
type GroupSelectionStore struct {
	path string

	mu         sync.Mutex
	loaded     bool
	selections map[string]string
}

// NewGroupSelectionStore creates a store at path. The parent directory is
// created lazily by Load, Save, and Set so merely constructing a store has no
// filesystem side effects.
func NewGroupSelectionStore(path string) *GroupSelectionStore {
	return &GroupSelectionStore{
		path:       path,
		selections: make(map[string]string),
	}
}

// NewDefaultGroupSelectionStore creates the store below configDir/persist.d.
func NewDefaultGroupSelectionStore(configDir string) *GroupSelectionStore {
	return NewGroupSelectionStore(filepath.Join(configDir, GroupSelectionStateRelativePath))
}

// Path returns the configured state path.
func (s *GroupSelectionStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Load reads the current state. A missing state file is normal and returns nil.
// Malformed, unsafe, or inaccessible state is returned as an error and leaves
// the in-memory state empty; callers should warn and continue startup.
func (s *GroupSelectionStore) Load() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.selections = make(map[string]string)
	s.loaded = true
	return s.loadFromDiskLocked()
}

// Save publishes the in-memory state with a 0600 temporary file, fsync, an
// atomic rename, and a directory fsync. Set should be preferred when updating
// one selection because it refreshes the on-disk state while holding the file
// lock.
func (s *GroupSelectionStore) Save() error {
	if s == nil {
		return errors.New("nil group selection store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		if err := s.loadFromDiskLocked(); err != nil {
			// Save is an explicit caller action. Do not silently overwrite a
			// state file that could not be inspected.
			return err
		}
		s.loaded = true
	}
	return s.saveLocked()
}

// Set records one logical member selection and durably publishes it. The
// member is validated before any state is written.
func (s *GroupSelectionStore) Set(groupName, memberName string) error {
	if s == nil {
		return errors.New("nil group selection store")
	}
	if err := validateSelectionToken(groupName, "group"); err != nil {
		return err
	}
	if err := validateSelectionToken(memberName, "member"); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureDirectoryLocked(); err != nil {
		return err
	}
	lock, err := s.acquireFileLockLocked()
	if err != nil {
		return err
	}
	defer lock.close()

	// Refresh while holding the inter-process lock so two dae processes do not
	// lose each other's selections when they update different groups.
	s.selections = make(map[string]string)
	if err := s.loadFromDiskLocked(); err != nil && !os.IsNotExist(err) {
		return err
	}
	s.selections[groupName] = memberName
	s.loaded = true
	return s.saveLockedWithoutLock()
}

// Apply resolves a persisted member identity against the current ordered
// members. It never returns an error for stale state: a missing group entry,
// a missing member, or a failed initial load all safely select the first
// current member and expose a warning in the result.
func (s *GroupSelectionStore) Apply(groupName string, members []string) GroupSelectionApplyResult {
	result := GroupSelectionApplyResult{GroupName: groupName, Index: -1}
	if len(members) == 0 {
		result.UsedFallback = true
		result.Warning = "group has no current members"
		return result
	}

	if s == nil {
		result.SelectedMember = members[0]
		result.Index = 0
		result.UsedFallback = true
		result.Warning = "selection store is unavailable; using first member"
		return result
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		s.selections = make(map[string]string)
		s.loaded = true
		if err := s.loadFromDiskLocked(); err != nil && !os.IsNotExist(err) {
			// The caller must be able to build a configuration even when the
			// optional state file is damaged or unreadable.
			result.Warning = "selection state could not be loaded; using first member"
		}
	}

	requested, exists := s.selections[groupName]
	result.RequestedMember = requested
	if exists {
		for index, member := range members {
			if member == requested {
				result.SelectedMember = member
				result.Index = index
				return result
			}
		}
		result.Warning = "persisted member is no longer present; using first member"
	} else if result.Warning == "" {
		result.Warning = "no persisted member; using first member"
	}

	result.SelectedMember = members[0]
	result.Index = 0
	result.UsedFallback = true
	return result
}

// Snapshot returns a copy of the currently loaded state. It is intended for
// diagnostics and tests; values are identities only.
func (s *GroupSelectionStore) Snapshot() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]string, len(s.selections))
	for group, member := range s.selections {
		result[group] = member
	}
	return result
}

func (s *GroupSelectionStore) ensureDirectoryLocked() error {
	if s.path == "" {
		return errors.New("group selection store path is empty")
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, groupSelectionDirMode); err != nil {
		return fmt.Errorf("create group selection directory: %w", err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat group selection directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("group selection state parent is not a directory")
	}
	if err := os.Chmod(directory, groupSelectionDirMode); err != nil {
		return fmt.Errorf("protect group selection directory: %w", err)
	}
	return nil
}

func (s *GroupSelectionStore) loadFromDiskLocked() error {
	if err := s.ensureDirectoryLocked(); err != nil {
		return err
	}
	info, err := os.Lstat(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect group selection state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("group selection state is not a regular file")
	}
	if info.Mode().Perm() != groupSelectionFileMode {
		return fmt.Errorf("group selection state permissions are %04o, want 0600", info.Mode().Perm())
	}
	body, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read group selection state: %w", err)
	}
	if len(body) > 1<<20 {
		return errors.New("group selection state is too large")
	}
	var state groupSelectionStateFile
	if err := json.Unmarshal(body, &state); err != nil {
		return fmt.Errorf("decode group selection state: %w", err)
	}
	if state.Version != groupSelectionStateVersion {
		return fmt.Errorf("unsupported group selection state version %d", state.Version)
	}
	if len(state.Selections) > groupSelectionMaxEntries {
		return errors.New("group selection state has too many entries")
	}
	for groupName, memberName := range state.Selections {
		if err := validateSelectionToken(groupName, "group"); err != nil {
			return fmt.Errorf("invalid group selection key: %w", err)
		}
		if err := validateSelectionToken(memberName, "member"); err != nil {
			return fmt.Errorf("invalid group selection value: %w", err)
		}
	}
	if state.Selections == nil {
		state.Selections = make(map[string]string)
	}
	s.selections = state.Selections
	return nil
}

func (s *GroupSelectionStore) saveLocked() error {
	if err := s.ensureDirectoryLocked(); err != nil {
		return err
	}
	lock, err := s.acquireFileLockLocked()
	if err != nil {
		return err
	}
	defer lock.close()
	return s.saveLockedWithoutLock()
}

func (s *GroupSelectionStore) saveLockedWithoutLock() error {
	state := groupSelectionStateFile{
		Version:    groupSelectionStateVersion,
		Selections: make(map[string]string, len(s.selections)),
	}
	for groupName, memberName := range s.selections {
		state.Selections[groupName] = memberName
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode group selection state: %w", err)
	}
	body = append(body, '\n')

	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create group selection temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	keepTemporary := false
	defer func() {
		if !keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(groupSelectionFileMode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect group selection temporary file: %w", err)
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write group selection temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync group selection temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close group selection temporary file: %w", err)
	}
	if info, err := os.Lstat(s.path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("group selection state is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect group selection destination: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace group selection state: %w", err)
	}
	keepTemporary = true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open group selection directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync group selection directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close group selection directory: %w", err)
	}
	return nil
}

type groupSelectionFileLock struct {
	file *os.File
}

func (s *GroupSelectionStore) acquireFileLockLocked() (*groupSelectionFileLock, error) {
	lockPath := filepath.Join(filepath.Dir(s.path), groupSelectionLockName)
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, groupSelectionFileMode)
	if err != nil {
		return nil, fmt.Errorf("open group selection lock: %w", err)
	}
	if err := file.Chmod(groupSelectionFileMode); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("protect group selection lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock group selection state: %w", err)
	}
	return &groupSelectionFileLock{file: file}, nil
}

func (lock *groupSelectionFileLock) close() {
	if lock == nil || lock.file == nil {
		return
	}
	_ = unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	_ = lock.file.Close()
	lock.file = nil
}

func validateSelectionToken(value, kind string) error {
	if value == "" {
		return fmt.Errorf("group selection %s is empty", kind)
	}
	if len(value) > groupSelectionMaxTokenSize {
		return fmt.Errorf("group selection %s is too long", kind)
	}
	for index, char := range value {
		if (index == 0 && !isSelectionIdentifierStart(char)) ||
			(index > 0 && !isSelectionIdentifierPart(char)) {
			return fmt.Errorf("group selection %s is not a safe identifier", kind)
		}
	}
	return nil
}

func isSelectionIdentifierStart(char rune) bool {
	return char == '_' || char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z'
}

func isSelectionIdentifierPart(char rune) bool {
	return isSelectionIdentifierStart(char) || char >= '0' && char <= '9' || char == '-'
}

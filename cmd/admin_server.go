/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/sirupsen/logrus"
)

const (
	adminReadTimeout     = 10 * time.Second
	adminWriteTimeout    = 30 * time.Second
	adminShutdownTimeout = 2 * time.Second
	adminMaxLogLines     = 500
	adminDefaultLogLines = 200
	adminMaxBodyBytes    = 1 << 12
)

type adminPlane interface {
	AdminGroups() []control.AdminGroup
	AdminStatusSnapshot(version string) control.AdminStatus
	SetGroupSelection(groupName, memberName string) error
	TriggerLatencyChecksForGroup(groupName string) error
	AdminConnections(limit int, outbound, src, mac string) control.AdminConnectionsSnapshot
}

type adminPlaneProvider func() adminPlane

type adminReloadFunc func() bool

type adminServer struct {
	mu        sync.Mutex
	http      *http.Server
	listen    string
	secret    string
	logFile   string
	configDir string
	log       *logrus.Logger
	plane     adminPlaneProvider
	reload    adminReloadFunc
}

type adminGroupPutBody struct {
	Member string `json:"member"`
}

type adminErrorBody struct {
	Error string `json:"error"`
}

type adminStatusBody struct {
	control.AdminStatus
	Generation         string `json:"generation,omitempty"`
	PreviousGeneration string `json:"previous_generation,omitempty"`
	SyncWarning        string `json:"sync_warning,omitempty"`
}

type adminLogsBody struct {
	Lines []string `json:"lines"`
}

type adminReloadBody struct {
	Queued bool `json:"queued"`
}

type adminGenerationMetadata struct {
	Generation         string `json:"generation"`
	PreviousGeneration string `json:"previous_generation"`
}

type adminSyncState struct {
	Warning    string `json:"warning"`
	Generation string `json:"generation"`
}

func newAdminServer(log *logrus.Logger, logFile, configDir string, plane adminPlaneProvider, reload adminReloadFunc) *adminServer {
	return &adminServer{
		logFile:   logFile,
		configDir: configDir,
		log:       log,
		plane:     plane,
		reload:    reload,
	}
}

func (s *adminServer) refresh(listen, secret string) {
	if s == nil {
		return
	}
	listen = strings.TrimSpace(listen)
	secret = strings.TrimSpace(secret)

	s.mu.Lock()
	defer s.mu.Unlock()

	if listen == s.listen && secret == s.secret && (s.http != nil || listen == "") {
		return
	}
	s.stopLocked()
	s.listen = listen
	s.secret = secret
	if listen == "" {
		return
	}
	if err := config.ValidateAdminListen(listen); err != nil {
		s.warnf("admin HTTP disabled: %v", err)
		return
	}
	if secret == "" {
		s.warnf("admin HTTP disabled: admin_secret is empty")
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.withAdminAuth(s.handleStatus))
	mux.HandleFunc("/v1/groups", s.withAdminAuth(s.handleGroups))
	mux.HandleFunc("/v1/groups/", s.withAdminAuth(s.handleGroup))
	mux.HandleFunc("/v1/connections", s.withAdminAuth(s.handleConnections))
	mux.HandleFunc("/v1/config", s.withAdminAuth(s.handleConfig))
	mux.HandleFunc("/v1/reload", s.withAdminAuth(s.handleReload))
	mux.HandleFunc("/v1/logs", s.withAdminAuth(s.handleLogs))
	server := &http.Server{
		Addr:         listen,
		Handler:      s.withAdminCORS(mux),
		ReadTimeout:  adminReadTimeout,
		WriteTimeout: adminWriteTimeout,
	}
	s.http = server
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.warnf("admin HTTP listen failed (tproxy continues): %v", err)
		}
	}()
	s.infof("admin HTTP listening on %s", listen)
}

func (s *adminServer) shutdown() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *adminServer) stopLocked() {
	if s.http == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), adminShutdownTimeout)
	_ = s.http.Shutdown(ctx)
	cancel()
	s.http = nil
}

func (s *adminServer) withAdminCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && adminOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *adminServer) withAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminBearerOK(r.Header.Get("Authorization"), s.secret) {
			writeAdminError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (s *adminServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	plane := s.currentPlane()
	body := adminStatusBody{
		AdminStatus: control.AdminStatus{Version: Version, Running: plane != nil},
	}
	if plane != nil {
		body.AdminStatus = plane.AdminStatusSnapshot(Version)
	}
	if meta, err := readAdminGenerationMetadata(s.configDir); err == nil {
		body.Generation = meta.Generation
		body.PreviousGeneration = meta.PreviousGeneration
	}
	if syncState, err := readAdminSyncState(); err == nil {
		body.SyncWarning = syncState.Warning
		if body.Generation == "" {
			body.Generation = syncState.Generation
		}
	}
	writeAdminJSON(w, http.StatusOK, body)
}

func (s *adminServer) handleGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "control plane is not ready")
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]any{"groups": plane.AdminGroups()})
}

func (s *adminServer) handleGroup(w http.ResponseWriter, r *http.Request) {
	name, action, err := parseAdminGroupPath(r.URL.Path)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, err.Error())
		return
	}
	if action == "delay" {
		if r.Method != http.MethodPost {
			writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		plane := s.currentPlane()
		if plane == nil {
			writeAdminError(w, http.StatusServiceUnavailable, "control plane is not ready")
			return
		}
		if err := plane.TriggerLatencyChecksForGroup(name); err != nil {
			writeAdminError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeAdminJSON(w, http.StatusAccepted, map[string]string{"group": name, "action": "delay"})
		return
	}
	if r.Method != http.MethodPut {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, adminMaxBodyBytes)
	var body adminGroupPutBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid json")
		return
	}
	body.Member = strings.TrimSpace(body.Member)
	if body.Member == "" {
		writeAdminError(w, http.StatusBadRequest, "member is required")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "control plane is not ready")
		return
	}
	if err := plane.SetGroupSelection(name, body.Member); err != nil {
		writeAdminError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeAdminJSON(w, http.StatusOK, map[string]string{"group": name, "member": body.Member})
}

func (s *adminServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	plane := s.currentPlane()
	if plane == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "control plane is not ready")
		return
	}
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := parsePositiveInt(raw, 1024)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = parsed
	}
	snap := plane.AdminConnections(limit, r.URL.Query().Get("outbound"), r.URL.Query().Get("src"), r.URL.Query().Get("mac"))
	writeAdminJSON(w, http.StatusOK, snap)
}

func (s *adminServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		body, err := loadAdminConfig(s.configDir)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, sanitizeAdminError(err))
			return
		}
		writeAdminJSON(w, http.StatusOK, body)
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, adminMaxConfigBytes)
		var body adminConfigBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid json")
			return
		}
		queued, err := applyAdminConfig(s.configDir, body, s.reload)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, sanitizeAdminError(err))
			return
		}
		writeAdminJSON(w, http.StatusOK, adminReloadBody{Queued: queued})
	default:
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *adminServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.reload == nil {
		writeAdminError(w, http.StatusServiceUnavailable, "reload is unavailable")
		return
	}
	if err := validateLoadedAdminConfig(s.configDir); err != nil {
		writeAdminError(w, http.StatusBadRequest, sanitizeAdminError(err))
		return
	}
	queued := s.reload()
	status := http.StatusAccepted
	if !queued {
		status = http.StatusConflict
	}
	writeAdminJSON(w, status, adminReloadBody{Queued: queued})
}

func (s *adminServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAdminError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	n := adminDefaultLogLines
	if raw := strings.TrimSpace(r.URL.Query().Get("n")); raw != "" {
		parsed, err := parsePositiveInt(raw, adminMaxLogLines)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid n")
			return
		}
		n = parsed
	}
	lines, err := tailLogLines(s.logFile, n)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeAdminJSON(w, http.StatusOK, adminLogsBody{Lines: []string{}})
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to read logs")
		return
	}
	writeAdminJSON(w, http.StatusOK, adminLogsBody{Lines: lines})
}

func (s *adminServer) currentPlane() adminPlane {
	if s == nil || s.plane == nil {
		return nil
	}
	return s.plane()
}

func (s *adminServer) warnf(format string, args ...any) {
	if s != nil && s.log != nil {
		s.log.Warnf(format, args...)
	}
}

func (s *adminServer) infof(format string, args ...any) {
	if s != nil && s.log != nil {
		s.log.Infof(format, args...)
	}
}

func adminBearerOK(header, secret string) bool {
	const prefix = "Bearer "
	if secret == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return got != "" && got == secret
}

func adminOriginAllowed(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	// LAN hostnames used by OpenWrt LuCI (router.lan, OpenWrt.lan).
	return strings.HasSuffix(strings.ToLower(host), ".lan")
}

func adminGroupNameFromPath(path string) (string, error) {
	name, action, err := parseAdminGroupPath(path)
	if err != nil || action != "" {
		return "", fmt.Errorf("invalid group")
	}
	return name, nil
}

func parseAdminGroupPath(path string) (name, action string, err error) {
	const prefix = "/v1/groups/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", fmt.Errorf("group is required")
	}
	rest := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	if rest == "" {
		return "", "", fmt.Errorf("group is required")
	}
	parts := strings.Split(rest, "/")
	name, err = url.PathUnescape(parts[0])
	if err != nil || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("invalid group")
	}
	if len(parts) == 1 {
		return name, "", nil
	}
	if len(parts) == 2 && parts[1] == "delay" {
		return name, "delay", nil
	}
	return "", "", fmt.Errorf("invalid group")
}

func writeAdminJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAdminError(w http.ResponseWriter, status int, message string) {
	writeAdminJSON(w, status, adminErrorBody{Error: message})
}

func parsePositiveInt(raw string, max int) (int, error) {
	n := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid integer")
		}
		n = n*10 + int(r-'0')
		if n > max {
			return max, nil
		}
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid integer")
	}
	return n, nil
}

func tailLogLines(path string, n int) ([]string, error) {
	if path == "" {
		return []string{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	lines := make([]string, 0, n)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !utf8.ValidString(line) {
			continue
		}
		lines = append(lines, line)
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return lines, nil
}

func readAdminGenerationMetadata(configDir string) (adminGenerationMetadata, error) {
	if configDir == "" {
		return adminGenerationMetadata{}, os.ErrNotExist
	}
	body, err := os.ReadFile(strings.TrimRight(configDir, "/") + "/metadata.json")
	if err != nil {
		return adminGenerationMetadata{}, err
	}
	var meta adminGenerationMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return adminGenerationMetadata{}, err
	}
	return meta, nil
}

func readAdminSyncState() (adminSyncState, error) {
	body, err := os.ReadFile("/var/run/kdae-last-sync.json")
	if err != nil {
		return adminSyncState{}, err
	}
	var state adminSyncState
	if err := json.Unmarshal(body, &state); err != nil {
		return adminSyncState{}, err
	}
	return state, nil
}

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func resetEffective(t *testing.T) {
	t.Helper()
	effectiveState.mu.Lock()
	effectiveState.current, effectiveState.pending = nil, nil
	effectiveState.mu.Unlock()
	t.Cleanup(func() {
		effectiveState.mu.Lock()
		effectiveState.current, effectiveState.pending = nil, nil
		effectiveState.mu.Unlock()
	})
}

func effectiveFixture(t *testing.T) *EffectiveConfig {
	t.Helper()
	resetEffective(t)
	_, configPath := writeMihomoFixture(t, testMihomoYAML)
	conf, _, err := readConfig(configPath)
	require.NoError(t, err)
	publishEffectiveConfig(conf)
	view := CurrentEffectiveConfig()
	require.NotNil(t, view)
	return view
}

func TestEffectiveConfigTellsWhereEachItemCameFrom(t *testing.T) {
	view := effectiveFixture(t)

	require.Len(t, view.Nodes, 3)
	require.Equal(t, EffectiveNode{Tag: "mine", Endpoint: "socks5 9.9.9.9:1080", Origin: originConfig}, view.Nodes[0])
	require.Equal(t, originMihomo, view.Nodes[1].Origin)
	require.Equal(t, "🇭🇰 HK 01", view.Nodes[1].DisplayName)
	require.Equal(t, "ss hk.example.com:8388", view.Nodes[1].Endpoint)

	names := make([]string, len(view.Groups))
	for i, g := range view.Groups {
		names[i] = g.Name
	}
	require.Equal(t, []string{"hand", "Rocket_Proxy", "node_sock"}, names)
	require.Equal(t, originConfig, view.Groups[0].Origin)
	require.Equal(t, "🚀 Proxy", view.Groups[1].DisplayName)
	require.Equal(t, originMihomo, view.Groups[1].Origin)
	require.True(t, view.Groups[2].Wrapper)

	// Hand-written rules first, then the Mihomo ones, rule sets unexpanded.
	require.GreaterOrEqual(t, len(view.Rules), 4)
	require.Equal(t, originConfig, view.Rules[0].Origin)
	require.Contains(t, view.Rules[0].Text, "dip(224.0.0.0/3)")
	require.Equal(t, originMihomo, view.Rules[1].Origin)
	require.Contains(t, view.Rules[1].Text, "ruleset(ads) -> block")
	for i, r := range view.Rules {
		require.Equal(t, i+1, r.Index)
	}

	require.Equal(t, EffectiveFallback{Outbound: "Rocket_Proxy", Origin: originMihomo}, view.Fallback)
	require.Len(t, view.RuleProviders, 1)
	require.Equal(t, originMihomo, view.RuleProviders[0].Origin)
	require.True(t, view.Mihomo.Enabled)
}

func TestEffectiveConfigNeverCarriesCredentials(t *testing.T) {
	view := effectiveFixture(t)
	body, err := json.Marshal(view)
	require.NoError(t, err)
	for _, secret := range []string{"pw", "ss://", "socks5://", "aes-128-gcm"} {
		require.NotContains(t, string(body), secret)
		require.NotContains(t, view.Text(), secret)
	}
}

func TestAdminServesTheEffectiveConfigReadOnly(t *testing.T) {
	view := effectiveFixture(t)
	server := newAdminServer(nil, "", t.TempDir(), nil, nil)
	server.secret = "token"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/config/effective", server.withAdminAuth(server.handleEffectiveConfig))

	do := func(method, target, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	require.Equal(t, http.StatusUnauthorized, do(http.MethodGet, "/v1/config/effective", "").Code)
	require.Equal(t, http.StatusMethodNotAllowed, do(http.MethodPut, "/v1/config/effective", "Bearer token").Code)
	require.Equal(t, http.StatusMethodNotAllowed, do(http.MethodPost, "/v1/config/effective", "Bearer token").Code)

	rec := do(http.MethodGet, "/v1/config/effective", "Bearer token")
	require.Equal(t, http.StatusOK, rec.Code)
	var got EffectiveConfig
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, len(view.Rules), len(got.Rules))
	require.Equal(t, "Rocket_Proxy", got.Fallback.Outbound)

	rec = do(http.MethodGet, "/v1/config/effective?format=text", "Bearer token")
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain"))
	text := rec.Body.String()
	require.Contains(t, text, "[config] mine")
	require.Contains(t, text, `[mihomo] HK_HK_01 ("🇭🇰 HK 01")  ss hk.example.com:8388`)
	require.Contains(t, text, "[mihomo] ruleset(ads) -> block")
	require.Contains(t, text, "fallback: [mihomo] Rocket_Proxy")
}

func TestAdminEffectiveConfigBeforeAnythingRuns(t *testing.T) {
	resetEffective(t)
	server := newAdminServer(nil, "", t.TempDir(), nil, nil)
	rec := httptest.NewRecorder()
	server.handleEffectiveConfig(rec, httptest.NewRequest(http.MethodGet, "/v1/config/effective", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestOnlyTheConfigurationThatRunsIsPublished(t *testing.T) {
	resetEffective(t)
	_, running := writeMihomoFixture(t, testMihomoYAML)
	runningConf, _, err := readConfig(running)
	require.NoError(t, err)

	// Another configuration is read (a validation, a reload that then fails)
	// but never starts running.
	_, other := writeMihomoFixture(t, strings.Replace(testMihomoYAML, "MATCH,🚀 Proxy", "MATCH,sock", 1))
	_, _, err = readConfig(other)
	require.NoError(t, err)

	publishEffectiveConfig(runningConf)
	require.Equal(t, "Rocket_Proxy", CurrentEffectiveConfig().Fallback.Outbound)
	require.Equal(t, originMihomo, CurrentEffectiveConfig().Fallback.Origin)
}

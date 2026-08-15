package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxMihomoRoutingSubscriptionBytes = 10 << 20

func loadMihomoRoutingSource(ctx context.Context, options SyncOptions) (body []byte, baseDir string, err error) {
	switch {
	case strings.TrimSpace(options.MihomoRoutingPath) != "":
		body, err = os.ReadFile(options.MihomoRoutingPath)
		if err != nil {
			return nil, "", errors.New("read Mihomo routing config failed")
		}
		baseDir, err = filepath.Abs(filepath.Dir(options.MihomoRoutingPath))
		if err != nil {
			return nil, "", errors.New("resolve Mihomo routing config directory failed")
		}
		return body, baseDir, nil
	case strings.TrimSpace(options.MihomoRoutingURL) != "", strings.TrimSpace(options.MihomoRoutingURLFile) != "":
		rawURL, err := resolveMihomoRoutingURL(options)
		if err != nil {
			return nil, "", err
		}
		body, err = fetchMihomoRoutingSubscription(ctx, options.Client, rawURL)
		if err != nil {
			return nil, "", err
		}
		baseDir, err = persistFetchedMihomoRouting(options.GenerationDir, body)
		if err != nil {
			return nil, "", err
		}
		return body, baseDir, nil
	default:
		return nil, "", errors.New("Mihomo routing source is empty")
	}
}

func resolveMihomoRoutingURL(options SyncOptions) (string, error) {
	raw := strings.TrimSpace(options.MihomoRoutingURL)
	if file := strings.TrimSpace(options.MihomoRoutingURLFile); file != "" {
		body, err := os.ReadFile(file)
		if err != nil {
			return "", errors.New("read Mihomo routing URL file failed")
		}
		raw = strings.TrimSpace(string(body))
	}
	raw = normalizeMihomoRoutingFetchURL(raw)
	if err := validateMihomoRoutingSubscriptionURL(raw); err != nil {
		return "", err
	}
	return raw, nil
}

func normalizeMihomoRoutingFetchURL(raw string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "https-file://"):
		return "https://" + strings.TrimPrefix(raw, "https-file://")
	case strings.HasPrefix(raw, "http-file://"):
		return "http://" + strings.TrimPrefix(raw, "http-file://")
	default:
		return raw
	}
}

func validateMihomoRoutingSubscriptionURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return errors.New("Mihomo routing subscription URL is invalid")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return nil
	default:
		return errors.New("Mihomo routing subscription must be http or https")
	}
}

func fetchMihomoRoutingSubscription(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("create Mihomo routing subscription request failed")
	}
	req.Header.Set("User-Agent", "dae-rule-sync")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("fetch Mihomo routing subscription failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch Mihomo routing subscription failed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMihomoRoutingSubscriptionBytes+1))
	if err != nil {
		return nil, errors.New("read Mihomo routing subscription failed")
	}
	if len(body) > maxMihomoRoutingSubscriptionBytes {
		return nil, errors.New("Mihomo routing subscription exceeds 10MB")
	}
	return body, nil
}

func persistFetchedMihomoRouting(generationDir string, body []byte) (string, error) {
	if generationDir == "" {
		return "", errors.New("generation-dir is required for subscription routing")
	}
	dir := filepath.Join(generationDir, "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", errors.New("create Mihomo routing cache directory failed")
	}
	path := filepath.Join(dir, "mihomo-routing.yaml")
	if err := writeFileSync(path, body, 0o600); err != nil {
		return "", errors.New("persist fetched Mihomo routing config failed")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", errors.New("resolve fetched Mihomo routing directory failed")
	}
	return abs, nil
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/daeuniverse/dae/pkg/geodata"
	"google.golang.org/protobuf/proto"
)

type DATWriteReport struct {
	Code      string
	Generated int
	Skipped   int
	SHA256    string
}

func writeGeoSiteDAT(path, code string, rules []DomainRule) (DATWriteReport, error) {
	if code == "" {
		return DATWriteReport{}, fmt.Errorf("geosite code is required")
	}
	if len(rules) == 0 {
		return DATWriteReport{}, fmt.Errorf("geosite rules are required")
	}

	domains := make([]*geodata.Domain, 0, len(rules))
	for _, rule := range rules {
		if rule.Value == "" {
			return DATWriteReport{}, fmt.Errorf("geosite %s domain value is required", rule.Kind)
		}
		kind, err := geoSiteDomainType(rule.Kind)
		if err != nil {
			return DATWriteReport{}, err
		}
		domains = append(domains, &geodata.Domain{Type: kind, Value: rule.Value})
	}

	body, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		CountryCode: code,
		Code:        code,
		Domain:      domains,
	}}})
	if err != nil {
		return DATWriteReport{}, fmt.Errorf("marshal geosite DAT: %w", err)
	}
	return publishDAT(path, code, len(domains), 0, body)
}

func writeGeoIPDAT(path, code string, prefixes []netip.Prefix) (DATWriteReport, error) {
	if code == "" {
		return DATWriteReport{}, fmt.Errorf("geoip code is required")
	}
	if len(prefixes) == 0 {
		return DATWriteReport{}, fmt.Errorf("geoip prefixes are required")
	}

	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	cidrs := make([]*geodata.CIDR, 0, len(prefixes))
	skipped := 0
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return DATWriteReport{}, fmt.Errorf("invalid geoip prefix")
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			skipped++
			continue
		}
		seen[prefix] = struct{}{}
		cidrs = append(cidrs, &geodata.CIDR{
			Ip:     append([]byte(nil), prefix.Addr().AsSlice()...),
			Prefix: uint32(prefix.Bits()),
		})
	}

	body, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{{
		CountryCode: code,
		Code:        code,
		Cidr:        cidrs,
	}}})
	if err != nil {
		return DATWriteReport{}, fmt.Errorf("marshal geoip DAT: %w", err)
	}
	return publishDAT(path, code, len(cidrs), skipped, body)
}

func geoSiteDomainType(kind DomainKind) (geodata.Domain_Type, error) {
	switch kind {
	case DomainFull:
		return geodata.Domain_Full, nil
	case DomainSuffix:
		return geodata.Domain_RootDomain, nil
	case DomainKeyword:
		return geodata.Domain_Plain, nil
	case DomainRegex:
		return geodata.Domain_Regex, nil
	default:
		return 0, fmt.Errorf("unsupported geosite domain kind %q", kind)
	}
}

func publishDAT(path, code string, generated, skipped int, body []byte) (DATWriteReport, error) {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".dae-rule-sync-dat-*.tmp")
	if err != nil {
		return DATWriteReport{}, fmt.Errorf("create DAT temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		if !published {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return DATWriteReport{}, fmt.Errorf("set DAT temporary file permissions: %w", err)
	}
	if written, err := temporary.Write(body); err != nil {
		return DATWriteReport{}, fmt.Errorf("write DAT temporary file: %w", err)
	} else if written != len(body) {
		return DATWriteReport{}, fmt.Errorf("write DAT temporary file: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		return DATWriteReport{}, fmt.Errorf("sync DAT temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return DATWriteReport{}, fmt.Errorf("close DAT temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return DATWriteReport{}, fmt.Errorf("publish DAT file: %w", err)
	}
	published = true
	if err := syncDirectory(directory); err != nil {
		return DATWriteReport{}, fmt.Errorf("sync DAT directory: %w", err)
	}

	digest := sha256.Sum256(body)
	return DATWriteReport{
		Code:      code,
		Generated: generated,
		Skipped:   skipped,
		SHA256:    hex.EncodeToString(digest[:]),
	}, nil
}

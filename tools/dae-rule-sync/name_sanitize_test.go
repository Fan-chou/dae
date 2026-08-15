package main

import (
	"strings"
	"testing"
)

func TestSanitizeMihomoNodeNamesKeepsReadableTokens(t *testing.T) {
	cases := map[string]string{
		"ss-node":                      "ss-node",
		"name with spaces":             "name_with_spaces",
		`name'with"quotes`:             "name_with_quotes",
		"🇭🇰 DMIT.HK | Hysteria":        "HK_DMIT_HK_Hysteria",
		"🇭🇰 BsetVM.HKBGP | AnyTLS":     "HK_BsetVM_HKBGP_AnyTLS",
		"🇭🇰 GG.IPLC -> Dmit.HK":        "HK_GG_IPLC_Dmit_HK",
		"🇭🇰 GG.IPLC -> Dmit.HK | gRPC": "HK_GG_IPLC_Dmit_HK_gRPC",
		"🇸🇬 NNC.SG | Hysteria":         "SG_NNC_SG_Hysteria",
		"🇺🇸 Dmit.LAX | Hysteria":       "US_Dmit_LAX_Hysteria",
		"🇺🇸 GG.IPLC -> Dmit.LAX":       "US_GG_IPLC_Dmit_LAX",
		"🇸🇬 GG.IPLC -> NNC.SG":         "SG_GG_IPLC_NNC_SG",
		"Telegram-HK":                  "Telegram-HK",
		"123abc":                       "n_123abc",
	}
	for original, want := range cases {
		if got := safeMihomoNodeName(original); got != want {
			t.Errorf("safeMihomoNodeName(%q) = %q, want %q", original, got, want)
		}
	}
}

func TestSanitizeDaeGroupNamesKeepsReadableTokens(t *testing.T) {
	cases := map[string]string{
		"AI":               "AI",
		"Dmit":             "Dmit",
		"Google":           "Google",
		"GGIPLC-KeepAlive": "GGIPLC_KeepAlive",
		"⛽ YouTuBe":        "Fuel_YouTuBe",
		"❤️ AI":            "Heart_AI",
		"❤️ Game":          "Heart_Game",
		"❤️ Google":        "Heart_Google",
		"❤️ Netflix":       "Heart_Netflix",
		"❤️ Proxy":         "Heart_Proxy",
		"❤️ Spotify":       "Heart_Spotify",
		"❤️ Telegram-HK":   "Heart_Telegram_HK",
		"❤️ YouTuBe":       "Heart_YouTuBe",
		"🇨🇳 CN":            "CN_CN",
		"🇭🇰 Telegram-HK":   "HK_Telegram_HK",
		"🍎 Apple":          "Apple_Apple",
		"🍎 Proxy":          "Apple_Proxy",
		"🍎 Speedtest":      "Apple_Speedtest",
		"🍒":                "Cherry",
		"🍒 Apple":          "Cherry_Apple",
		"🍒 Proxy":          "Cherry_Proxy",
		"🍒 Speedtest":      "Cherry_Speedtest",
		"🍿 Netflix":        "Popcorn_Netflix",
		"🎮 Game":           "Game_Game",
		"🎮 Steam":          "Game_Steam",
		"🎮 SteamCN":        "Game_SteamCN",
		"🎯 Final":          "Target_Final",
		"🎵 Spotify":        "Music_Spotify",
		"🏠 Microsoft":      "Home_Microsoft",
		"🐭 DisneyPlus":     "Mouse_DisneyPlus",
		"👛 PayPal":         "Wallet_PayPal",
		"💤 Prime Video":    "Zzz_Prime_Video",
		"📚 Duolingo":       "Book_Duolingo",
		"📺 DomesticMedia":  "TV_DomesticMedia",
		"📺 ForeignMedia":   "TV_ForeignMedia",
		"🫒 Hijacking":      "Olive_Hijacking",
	}
	seen := make(map[string]string, len(cases))
	for original, want := range cases {
		got := safeDaeIdentifier(original)
		if got != want {
			t.Errorf("safeDaeIdentifier(%q) = %q, want %q", original, got, want)
		}
		if !daeIdentifierPattern.MatchString(got) {
			t.Errorf("safeDaeIdentifier(%q) = %q, not a dae identifier", original, got)
		}
		if previous, exists := seen[got]; exists {
			t.Errorf("groups %q and %q collide as %q", previous, original, got)
		}
		seen[got] = original
	}
}

func TestSanitizeMihomoIdentifierFallsBackToHash(t *testing.T) {
	for _, name := range []string{"普通/节点", "普通节点", "🦄"} {
		got := safeMihomoNodeName(name)
		if !strings.HasPrefix(got, "mihomo_") || !mihomoNodeIdentifierPattern.MatchString(got) {
			t.Errorf("safeMihomoNodeName(%q) = %q, want hashed identifier", name, got)
		}
		if got != hashedMihomoIdentifier(name) {
			t.Errorf("safeMihomoNodeName(%q) = %q, want %q", name, got, hashedMihomoIdentifier(name))
		}
	}
	if got := safeDaeIdentifier("  direct  "); got != hashedMihomoIdentifier("  direct  ") {
		t.Errorf("safeDaeIdentifier(%q) = %q, want reserved-name hash", "  direct  ", got)
	}
	if got := safeDaeIdentifier("  block  "); got != hashedMihomoIdentifier("  block  ") {
		t.Errorf("safeDaeIdentifier(%q) = %q, want reserved-name hash", "  block  ", got)
	}
}

func TestSanitizeMihomoIdentifierTruncatesLongNames(t *testing.T) {
	longName := strings.Repeat("a", maxSafeIdentifier+1)
	got := safeMihomoNodeName(longName)
	if len(got) > maxSafeIdentifier || !mihomoNodeIdentifierPattern.MatchString(got) {
		t.Fatalf("long name mapped to %q", got)
	}
	if !strings.HasSuffix(got, "_"+identifierDisambiguator(longName)) {
		t.Fatalf("long name %q missing disambiguator suffix", got)
	}
}

func TestSanitizeMihomoIdentifierCollisionIsFailClosed(t *testing.T) {
	config := MihomoConfig{
		Proxies: []MihomoProxy{
			{Name: "❤️ Proxy", Type: "socks5", Server: "127.0.0.1", Port: 1080},
			{Name: "Heart Proxy", Type: "socks5", Server: "127.0.0.1", Port: 1080},
		},
	}
	if _, _, err := GenerateMihomoNodes(config); err == nil {
		t.Fatal("GenerateMihomoNodes() error = nil, want sanitized-name collision")
	}
}

package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	regionalIndicatorA = 0x1F1E6
	regionalIndicatorZ = 0x1F1FF
	maxSafeIdentifier  = 64
)

// Common Mihomo/Clash list emojis → short ASCII tokens. Unmapped emoji are
// dropped; if nothing usable remains, the caller falls back to a stable hash.
var mihomoEmojiAbbrev = map[rune]string{
	0x26FD:  "Fuel",    // ⛽
	0x2764:  "Heart",   // ❤ / ❤️
	0x2665:  "Heart",   // ♥
	0x1F495: "Heart",   // 💕
	0x1F496: "Heart",   // 💖
	0x1F497: "Heart",   // 💗
	0x1F498: "Heart",   // 💘
	0x1F499: "Heart",   // 💙
	0x1F49A: "Heart",   // 💚
	0x1F49B: "Heart",   // 💛
	0x1F49C: "Heart",   // 💜
	0x1F49D: "Heart",   // 💝
	0x1F5A4: "Heart",   // 🖤
	0x1F90D: "Heart",   // 🤍
	0x1F90E: "Heart",   // 🤎
	0x1F9E1: "Heart",   // 🧡
	0x1F34E: "Apple",   // 🍎
	0x1F352: "Cherry",  // 🍒
	0x1F37F: "Popcorn", // 🍿
	0x1F3AE: "Game",    // 🎮
	0x1F3AF: "Target",  // 🎯
	0x1F3B5: "Music",   // 🎵
	0x1F3E0: "Home",    // 🏠
	0x1F42D: "Mouse",   // 🐭
	0x1F45B: "Wallet",  // 👛
	0x1F4A4: "Zzz",     // 💤
	0x1F4DA: "Book",    // 📚
	0x1F4FA: "TV",      // 📺
	0x1FAD2: "Olive",   // 🫒
	0x1F680: "Rocket",  // 🚀
	0x1F525: "Fire",    // 🔥
	0x2B50:  "Star",    // ⭐
	0x1F31F: "Star",    // 🌟
	0x26A1:  "Bolt",    // ⚡
	0x1F310: "Global",  // 🌐
	0x1F512: "Lock",    // 🔒
	0x2708:  "Plane",   // ✈
	0x1F6EB: "Plane",   // 🛫
	0x1F4A1: "Idea",    // 💡
	0x1F3AC: "Movie",   // 🎬
	0x1F4F1: "Phone",   // 📱
	0x1F4BB: "PC",      // 💻
	0x2601:  "Cloud",   // ☁
	0x1F6E1: "Shield",  // 🛡
}

func hashedMihomoIdentifier(name string) string {
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("mihomo_%x", digest[:6])
}

func identifierDisambiguator(name string) string {
	digest := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", digest[:3])
}

func safeMihomoNodeName(name string) string {
	if len(name) <= maxMihomoNodeNameLength && mihomoNodeIdentifierPattern.MatchString(name) {
		return name
	}
	return sanitizeMihomoIdentifier(name, true)
}

func safeDaeIdentifier(name string) string {
	if daeIdentifierPattern.MatchString(name) {
		return name
	}
	return sanitizeMihomoIdentifier(name, false)
}

func sanitizeMihomoIdentifier(name string, allowHyphen bool) string {
	if !utf8.ValidString(name) {
		return hashedMihomoIdentifier(name)
	}
	parts := make([]string, 0, 8)
	var word strings.Builder
	flushWord := func() {
		token := strings.Trim(word.String(), "-_")
		word.Reset()
		if token != "" {
			parts = append(parts, token)
		}
	}
	appendToken := func(token string) {
		if token == "" {
			return
		}
		flushWord()
		parts = append(parts, token)
	}

	runes := []rune(name)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if isMihomoNameIgnorable(r) {
			continue
		}
		if i+1 < len(runes) {
			if a, ok := regionalIndicatorLetter(r); ok {
				if b, ok := regionalIndicatorLetter(runes[i+1]); ok {
					appendToken(string([]byte{a, b}))
					i++
					continue
				}
			}
			if (r == '-' || r == '=') && runes[i+1] == '>' {
				flushWord()
				i++
				continue
			}
		}
		if token, ok := mihomoEmojiAbbrev[r]; ok {
			appendToken(token)
			continue
		}
		if r <= 127 && (r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || allowHyphen && r == '-') {
			word.WriteByte(byte(r))
			continue
		}
		if r == '-' || isMihomoNameSeparator(r) {
			flushWord()
			continue
		}
	}
	flushWord()

	sanitized := strings.Join(parts, "_")
	sanitized = collapseIdentifierUnderscores(sanitized)
	if sanitized == "" || sanitized == "_" {
		return hashedMihomoIdentifier(name)
	}
	if sanitized[0] >= '0' && sanitized[0] <= '9' {
		sanitized = "n_" + sanitized
	}
	if sanitized == "direct" || sanitized == "block" {
		return hashedMihomoIdentifier(name)
	}
	if len(sanitized) > maxSafeIdentifier {
		suffix := identifierDisambiguator(name)
		keep := maxSafeIdentifier - 1 - len(suffix)
		if keep < 1 {
			return hashedMihomoIdentifier(name)
		}
		sanitized = strings.Trim(sanitized[:keep], "_") + "_" + suffix
	}
	if allowHyphen {
		if !mihomoNodeIdentifierPattern.MatchString(sanitized) {
			return hashedMihomoIdentifier(name)
		}
	} else if !daeIdentifierPattern.MatchString(sanitized) {
		return hashedMihomoIdentifier(name)
	}
	return sanitized
}

func regionalIndicatorLetter(r rune) (byte, bool) {
	if r < regionalIndicatorA || r > regionalIndicatorZ {
		return 0, false
	}
	return byte('A' + (r - regionalIndicatorA)), true
}

func isMihomoNameIgnorable(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFE0E, 0xFE0F, 0x20E3:
		return true
	default:
		return false
	}
}

func isMihomoNameSeparator(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case '|', '/', '\\', '.', ',', ':', ';', '\'', '"', '`',
		'(', ')', '[', ']', '{', '}', '<', '>',
		'+', '=', '*', '?', '&', '%', '#', '@', '!', '~',
		0x00B7, 0x2013, 0x2014, 0x2022, 0x30FB, // · – — • ・
		0x2192, // →
		0x21D2: // ⇒
		return true
	default:
		return false
	}
}

func collapseIdentifierUnderscores(name string) string {
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	return strings.Trim(name, "_")
}

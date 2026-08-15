/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"unicode"
)

var (
	httpHeaderHost = []byte("host")
	httpHeaderSep  = []byte{':'}
	httpSchemeSep  = []byte("://")
	httpConnect    = []byte("CONNECT")
	httpStar       = []byte("*")
)

// httpMethods lists valid HTTP request methods as []byte so the method check
// in SniffHttp is allocation-free (string(method) would heap-allocate per call
// on a hot path).
var httpMethods = [][]byte{
	[]byte("GET"), []byte("POST"), []byte("PUT"), []byte("PATCH"),
	[]byte("DELETE"), []byte("COPY"), []byte("HEAD"), []byte("OPTIONS"),
	[]byte("LINK"), []byte("UNLINK"), []byte("PURGE"), []byte("LOCK"),
	[]byte("UNLOCK"), []byte("PROPFIND"), []byte("CONNECT"), []byte("TRACE"),
}

// isValidHttpMethod reports whether method is a recognized HTTP method,
// comparing bytes directly to avoid a string conversion.
func isValidHttpMethod(method []byte) bool {
	for _, m := range httpMethods {
		if bytes.Equal(method, m) {
			return true
		}
	}
	return false
}

func isIncompleteHttpMethodPrefix(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(m, head) {
			return true
		}
	}
	return false
}

func hostFromAbsoluteURI(target []byte) string {
	scheme := bytes.Index(target, httpSchemeSep)
	if scheme < 0 {
		return ""
	}
	rest := target[scheme+len(httpSchemeSep):]
	if at := bytes.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if slash := bytes.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	if len(rest) == 0 {
		return ""
	}
	return string(rest)
}

func hostFromRequestLine(requestLine []byte) string {
	method, rest, found := bytes.Cut(requestLine, []byte(" "))
	if !found {
		return ""
	}
	target, _, found := bytes.Cut(bytes.TrimLeft(rest, " "), []byte(" "))
	if !found {
		target = bytes.TrimSpace(rest)
	}
	target = bytes.TrimSpace(target)
	if len(target) == 0 || bytes.Equal(target, httpStar) {
		return ""
	}
	if bytes.Equal(method, httpConnect) {
		return string(target)
	}
	return hostFromAbsoluteURI(target)
}

func sniffHTTPHostHeader(data []byte) (string, error) {
	// The first line is the request line ("METHOD SP target SP version"); it is
	// never a Host header, so jump past it to avoid a wasted scan per request.
	start := 0
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return "", ErrNeedMore
	}
	requestLine := data[:nl]
	if n := len(requestLine); n > 0 && requestLine[n-1] == '\r' {
		requestLine = requestLine[:n-1]
	}
	start = nl + 1
	for start < len(data) {
		// Split on LF. HTTP lines end with CRLF, and a single-byte search for
		// '\n' is markedly cheaper than a two-byte search for "\r\n"; the
		// preceding CR (if present) is stripped from the header content.
		nl := bytes.IndexByte(data[start:], '\n')
		if nl < 0 {
			// A later Host line (or the rest of the current one) has not
			// arrived yet. Wait instead of giving up the way we used to
			// with ErrNotFound — prefetch often stops after the request line.
			return "", ErrNeedMore
		}
		lineEnd := start + nl
		var line []byte
		if lineEnd > start && data[lineEnd-1] == '\r' {
			line = data[start : lineEnd-1]
		} else {
			line = data[start:lineEnd]
		}
		start = lineEnd + 1

		// Empty line marks end-of-headers.
		if len(line) == 0 {
			if host := hostFromRequestLine(requestLine); host != "" {
				return host, nil
			}
			return "", ErrNotFound
		}
		key, value, found := bytes.Cut(line, httpHeaderSep)
		if !found {
			// Bad key value.
			continue
		}
		if bytes.EqualFold(bytes.TrimSpace(key), httpHeaderHost) {
			host := string(bytes.TrimSpace(value))
			if host == "" {
				return "", ErrNotFound
			}
			return host, nil
		}
	}
	return "", ErrNeedMore
}

func (s *Sniffer) SniffHttp() (d string, err error) {
	// First byte should be printable.
	if s.buf.Len() == 0 || !unicode.IsPrint(rune(s.buf.Bytes()[0])) {
		return "", ErrNotApplicable
	}

	// Search method.
	search := s.buf.Bytes()
	head := search
	if len(head) > 12 {
		head = head[:12]
	}
	method, _, found := bytes.Cut(head, []byte(" "))
	if !found {
		if isIncompleteHttpMethodPrefix(head) {
			return "", ErrNeedMore
		}
		return "", ErrNotApplicable
	}
	if !isValidHttpMethod(method) {
		return "", ErrNotApplicable
	}

	// Now we assume it is an HTTP packet. We should not return NotApplicableError after here.

	return sniffHTTPHostHeader(s.buf.Bytes())
}

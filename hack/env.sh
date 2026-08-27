#!/usr/bin/env bash
# Pin Go caches to durable directories. Source from the repo root:
#   . hack/env.sh
#
# Direct `go test` / `go build` (not going through make) still pick up the
# sandbox GOCACHE override; this undoes that for the current shell.

# This file lives at <repo>/hack/env.sh. KDAE_ROOT wins; git works from bash or zsh.
_kdae_root="${KDAE_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

_kdae_writable_dir() {
	mkdir -p "$1" 2>/dev/null || return 1
	touch "$1/.kdae-write" 2>/dev/null || return 1
	rm -f "$1/.kdae-write"
	return 0
}

_kdae_durable_gocache() {
	if _kdae_writable_dir "${HOME}/go-cache"; then
		printf '%s\n' "${HOME}/go-cache"
		return
	fi
	if _kdae_writable_dir "${HOME}/.cache/go-build"; then
		printf '%s\n' "${HOME}/.cache/go-build"
		return
	fi
	mkdir -p "${_kdae_root}/.gocache"
	printf '%s\n' "${_kdae_root}/.gocache"
}

case "${GOCACHE:-}" in
*cursor-sandbox-cache*|/tmp/*)
	export GOCACHE="$(_kdae_durable_gocache)"
	;;
esac

# Prefer the already-populated module cache over GOPATH/pkg/mod duplicates.
if [ -z "${GOMODCACHE:-}" ] && [ -d "${HOME}/go-mod/cache" ]; then
	export GOMODCACHE="${HOME}/go-mod"
fi

if [ -n "${GOTMPDIR:-}" ] && _kdae_writable_dir "${GOTMPDIR}"; then
	:
elif _kdae_writable_dir "${HOME}/go-tmp"; then
	export GOTMPDIR="${HOME}/go-tmp"
else
	mkdir -p "${_kdae_root}/.gotmp"
	export GOTMPDIR="${_kdae_root}/.gotmp"
fi

#!/bin/sh
# Same-origin reverse proxy so HTTPS /kdae-ui/ can call kdae /v1 without mixed content.
# Secrets stay in CGI env / a 0600 curl config; they are not logged.

set -eu

listen=$(uci -q get dae.config.admin_listen || true)
if [ -z "$listen" ]; then
	printf 'Status: 503\r\nContent-Type: application/json\r\n\r\n{"error":"admin_listen is empty"}\n'
	exit 0
fi

path=${PATH_INFO:-}
if [ -z "$path" ]; then
	uri=${REQUEST_URI:-}
	uri=${uri%%\?}
	path=${uri#/cgi-bin/kdae-proxy}
fi
case "$path" in
/v1/*) ;;
*)
	printf 'Status: 404\r\nContent-Type: application/json\r\n\r\n{"error":"not found"}\n'
	exit 0
	;;
esac

target="http://${listen}${path}"
if [ -n "${QUERY_STRING:-}" ]; then
	target="${target}?${QUERY_STRING}"
fi

auth=${HTTP_AUTHORIZATION:-}
if [ -z "$auth" ]; then
	auth=${HTTP_X_KDAE_AUTHORIZATION:-}
fi

umask 077
hdr=$(mktemp)
body=$(mktemp)
cfg=$(mktemp)
trap 'rm -f "$hdr" "$body" "$cfg"' EXIT

{
	echo 'silent'
	echo 'show-error'
	echo 'max-time = 10'
	echo 'http1.1'
	printf 'url = "%s"\n' "$target"
	printf 'request = "%s"\n' "${REQUEST_METHOD:-GET}"
	if [ -n "$auth" ]; then
		printf 'header = "Authorization: %s"\n' "$auth"
	fi
	if [ -n "${CONTENT_TYPE:-}" ]; then
		printf 'header = "Content-Type: %s"\n' "$CONTENT_TYPE"
	fi
} > "$cfg"

case "${REQUEST_METHOD:-GET}" in
PUT|POST)
	curl -K "$cfg" -D "$hdr" -o "$body" --data-binary @- </dev/stdin || true
	;;
*)
	curl -K "$cfg" -D "$hdr" -o "$body" || true
	;;
esac

status=$(awk 'NR==1 {print $2; exit}' "$hdr")
reason=$(awk 'NR==1 {$1=""; $2=""; sub(/^  */, ""); print; exit}' "$hdr" | tr -d '\r')
[ -n "$status" ] || status=502
[ -n "$reason" ] || reason=Error
printf 'Status: %s %s\n' "$status" "$reason"
ctype=$(awk -F': ' 'tolower($1)=="content-type" {gsub("\r",""); print $2; exit}' "$hdr")
[ -n "$ctype" ] || ctype='application/json'
printf 'Content-Type: %s\n\n' "$ctype"
cat "$body"

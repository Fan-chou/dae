#!/bin/sh
set -eu
umask 077
endpoint=${1:-status}
after=${2:-0}
case "$endpoint" in status|groups|capture|evidence) ;; *) exit 2 ;; esac
case "$after" in ''|*[!0-9]*) exit 2 ;; esac
secret=$(awk '
/^[[:space:]]*admin_secret:/ {
    sub(/^[^:]*:[[:space:]]*/, "")
    value = ""; quote = ""; escaped = 0
    for (i = 1; i <= length($0); i++) {
        ch = substr($0, i, 1)
        if (!escaped && quote == "" && ch == "#") break
        value = value ch
        if (escaped) { escaped = 0; continue }
        if (ch == "\\" && quote != "") { escaped = 1; continue }
        if (ch == quote) quote = ""
        else if (quote == "" && (ch == "\047" || ch == "\"")) quote = ch
    }
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
    first = substr(value, 1, 1)
    if ((first == "\047" || first == "\"") && substr(value, length(value), 1) == first)
        value = substr(value, 2, length(value) - 2)
    print value; exit
}' /etc/dae/local.dae)
[ -n "$secret" ]
printf 'header = "Authorization: Bearer %s"\n' "$secret" | curl -fsS --max-time 10 -K - "http://192.168.124.223:2025/v1/$endpoint?after=$after"

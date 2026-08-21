#!/bin/sh
# Print mihomo.node_name_map as JSON. No node URIs or credentials.
# Used by LuCI so rpcd does not have to read a symlinked metadata.json.

set -eu
META=""
if [ -f /etc/dae/current/metadata.json ]; then
	META=/etc/dae/current/metadata.json
elif [ -f /etc/dae/metadata.json ]; then
	META=/etc/dae/metadata.json
else
	printf '%s\n' '{}'
	exit 0
fi

if command -v jsonfilter >/dev/null 2>&1; then
	out=$(jsonfilter -i "$META" -e '@.mihomo.node_name_map' 2>/dev/null || true)
	if [ -n "$out" ]; then
		printf '%s\n' "$out"
		exit 0
	fi
fi

printf '%s\n' '{}'

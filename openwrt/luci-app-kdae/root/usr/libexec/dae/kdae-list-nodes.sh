#!/bin/sh
# Print the nodes that came from the Mihomo routing source as a JSON object
# {"name in the source": "name in dae"}. Asks the running dae; prints {} when it
# is not running. No node links or credentials are involved.

set -eu
CONFIG=$(uci -q get dae.config.config_file || echo /etc/dae/config.dae)
out=$(/usr/bin/dae mihomo status -c "$CONFIG" 2>/dev/null || true)
if [ -n "$out" ] && command -v jsonfilter >/dev/null 2>&1; then
	names=$(printf '%s' "$out" | jsonfilter -e '@.node_names' 2>/dev/null || true)
	if [ -n "$names" ]; then
		printf '%s\n' "$names"
		exit 0
	fi
fi
printf '%s\n' '{}'

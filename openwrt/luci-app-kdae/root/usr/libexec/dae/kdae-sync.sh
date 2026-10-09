#!/bin/sh
# Apply the UCI settings: write local.dae, validate the result, and hot-reload
# a running dae. dae itself fetches, converts and merges the Mihomo routing
# source on every start and reload (keeping the last good copy), so there is
# nothing to generate or publish here.
#
# Fail-closed: when validation fails, local.dae goes back to what it was, so
# the next reload or reboot does not load a rejected candidate.

set -eu

WRITE_LOCAL=${KDAE_WRITE_LOCAL:-/usr/libexec/dae/kdae-write-local.sh}
DAE=${KDAE_DAE:-/usr/bin/dae}
LOCAL_DAE=${KDAE_LOCAL_DAE:-/etc/dae/local.dae}
export KDAE_LOCAL_DAE="$LOCAL_DAE"

config=$(uci -q get dae.config.config_file || echo /etc/dae/config.dae)

bak=""
if [ -f "$LOCAL_DAE" ]; then
	bak="${LOCAL_DAE}.bak.$$"
	cp -p "$LOCAL_DAE" "$bak"
fi
trap '[ -z "$bak" ] || rm -f "$bak"' EXIT

restore() {
	if [ -n "$bak" ] && [ -f "$bak" ]; then
		mv -f "$bak" "$LOCAL_DAE"
	else
		rm -f "$LOCAL_DAE"
	fi
	bak=""
}

if ! "$WRITE_LOCAL"; then
	restore
	echo "failed to write local.dae from the UCI settings" >&2
	exit 1
fi

if ! "$DAE" validate -c "$config"; then
	restore
	echo "dae validate failed; local.dae was restored" >&2
	exit 1
fi

# `validate` passes while the Mihomo source cannot be reached, so that a router
# can boot before its uplink is up. Applying new settings is the moment to
# insist: read the source now, which also leaves a copy to fall back on.
if ! "$DAE" mihomo preview -c "$config" >/dev/null; then
	restore
	echo "the Mihomo routing source could not be read; local.dae was restored" >&2
	exit 1
fi

if /etc/init.d/dae running >/dev/null 2>&1; then
	/etc/init.d/dae hot_reload
	echo "reload requested; the new routing source is read now"
else
	echo "local.dae written; dae is not running, the routing source is read when it starts"
fi

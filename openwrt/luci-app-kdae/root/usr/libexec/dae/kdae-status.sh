#!/bin/sh
# Print the state of the Mihomo routing source of the running dae as JSON.
# Exits non-zero with a message when dae is not running.

set -eu
CONFIG=$(uci -q get dae.config.config_file || echo /etc/dae/config.dae)
exec /usr/bin/dae mihomo status -c "$CONFIG"

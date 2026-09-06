#!/bin/sh
# Fixed log target; bound both bytes read and lines returned to LuCI.
case "$1" in
  100|300|1000) lines="$1" ;;
  *) lines=300 ;;
esac
[ -f /var/log/dae/dae.log ] || exit 0
tail -c 1048576 /var/log/dae/dae.log | tail -n "$lines"

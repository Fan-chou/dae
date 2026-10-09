#!/bin/sh
# kdae-sync.sh must leave local.dae as it was when anything fails.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SCRIPT="$ROOT/root/usr/libexec/dae/kdae-sync.sh"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

# uci answers the config path only; /etc/init.d/dae is not touched because the
# stubbed validate fails or the service check below finds nothing running.
cat > "$tmp/bin/uci" <<'STUB'
#!/bin/sh
exit 1
STUB
chmod +x "$tmp/bin/uci"

cat > "$tmp/write-ok" <<'STUB'
#!/bin/sh
printf 'new\n' > "$KDAE_LOCAL_DAE"
STUB
cat > "$tmp/write-fail" <<'STUB'
#!/bin/sh
printf 'half-written\n' > "$KDAE_LOCAL_DAE"
exit 1
STUB
# dae stubs: validate and `mihomo preview` can be told to fail separately.
cat > "$tmp/dae-ok" <<'STUB'
#!/bin/sh
exit 0
STUB
cat > "$tmp/dae-bad" <<'STUB'
#!/bin/sh
echo "invalid config" >&2
exit 1
STUB
# validate passes (as it does offline), the source cannot be read
cat > "$tmp/dae-nosource" <<'STUB'
#!/bin/sh
[ "$1" = mihomo ] && { echo "cannot read the source" >&2; exit 1; }
exit 0
STUB
chmod +x "$tmp"/write-* "$tmp"/dae-*

run() {
	PATH="$tmp/bin:$PATH" KDAE_WRITE_LOCAL="$1" KDAE_DAE="$2" KDAE_LOCAL_DAE="$tmp/local.dae" sh "$SCRIPT" >/dev/null 2>&1
}

# validate fails: the previous local.dae comes back
printf 'old\n' > "$tmp/local.dae"
if run "$tmp/write-ok" "$tmp/dae-bad"; then fail "validate failure was reported as success"; fi
[ "$(cat "$tmp/local.dae")" = old ] || fail "local.dae not restored after validate failure"
ls "$tmp"/local.dae.bak.* >/dev/null 2>&1 && fail "backup left behind"

# the writer fails half way: same
if run "$tmp/write-fail" "$tmp/dae-ok"; then fail "writer failure was reported as success"; fi
[ "$(cat "$tmp/local.dae")" = old ] || fail "local.dae not restored after writer failure"

# first ever write fails validation: no file is left
rm -f "$tmp/local.dae"
if run "$tmp/write-ok" "$tmp/dae-bad"; then fail "validate failure was reported as success"; fi
[ ! -e "$tmp/local.dae" ] || fail "rejected first local.dae was kept"

# validate passes but the Mihomo source cannot be read: rejected as well
printf 'old\n' > "$tmp/local.dae"
if run "$tmp/write-ok" "$tmp/dae-nosource"; then fail "unreadable source was reported as success"; fi
[ "$(cat "$tmp/local.dae")" = old ] || fail "local.dae not restored when the source was unreadable"

# success keeps the new file and no backup
printf 'old\n' > "$tmp/local.dae"
run "$tmp/write-ok" "$tmp/dae-ok" || fail "good write failed"
[ "$(cat "$tmp/local.dae")" = new ] || fail "good write not kept"
ls "$tmp"/local.dae.bak.* >/dev/null 2>&1 && fail "backup left behind after success"

echo ok

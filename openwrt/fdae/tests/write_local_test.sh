#!/bin/sh
# write-local.sh renders the inbound UCI sections into local.dae, and refuses
# anything that would not be a safe, valid inbound.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SCRIPT="$ROOT/../files/write-local.sh"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

# A flat stand-in for uci: `uci -q get KEY` answers from $FAKE_UCI, whose lines
# are KEY=VALUE. A section "exists" when KEY=type is listed for it.
cat > "$tmp/bin/uci" <<'STUB'
#!/bin/sh
[ "$1" = "-q" ] && shift
[ "$1" = get ] || exit 1
line=$(grep -F -x -m1 -e "$2=*" "$FAKE_UCI" 2>/dev/null || true)
[ -n "$line" ] || line=$(grep -m1 -F -e "$2=" "$FAKE_UCI" || true)
[ -n "$line" ] || exit 1
printf '%s\n' "${line#*=}"
STUB
chmod +x "$tmp/bin/uci"

run() {
	PATH="$tmp/bin:$PATH" FAKE_UCI="$tmp/uci" FDAE_LOCAL_DAE="$tmp/local.dae" sh "$SCRIPT" 2>"$tmp/err"
}

reset() {
	rm -f "$tmp/local.dae"
	: > "$tmp/uci"
}

# --- nothing configured: no inbound block at all
reset
run || fail "empty configuration failed"
grep -q '^inbound' "$tmp/local.dae" && fail "an inbound block was written for no inbounds"

# --- a plain one, a full one, a disabled one
reset
cat > "$tmp/uci" <<'UCI'
dae.@inbound[0]=inbound
dae.@inbound[0].name=s1
dae.@inbound[0].listen=127.0.0.1:1080
dae.@inbound[1]=inbound
dae.@inbound[1].name=lan-2
dae.@inbound[1].listen=[fd00::1]:1081
dae.@inbound[1].username=alice
dae.@inbound[1].password=it's secret
dae.@inbound[1].udp=0
dae.@inbound[1].udp_advertise=203.0.113.7
dae.@inbound[1].sniff=off
dae.@inbound[1].resolve=deferred
dae.@inbound[2]=inbound
dae.@inbound[2].enabled=0
dae.@inbound[2].name=off
dae.@inbound[2].listen=127.0.0.1:1082
UCI
run || fail "valid inbounds were refused: $(cat "$tmp/err")"
out=$(cat "$tmp/local.dae")
for want in "^inbound {" "^    s1 {" "listen: '127.0.0.1:1080'" "^    lan-2 {" "listen: '\[fd00::1\]:1081'" \
	"username: 'alice'" 'password: "it'"'"'s secret"' "udp: false" "udp_advertise: '203.0.113.7'" "sniff: off" "resolve: deferred"; do
	printf '%s\n' "$out" | grep -q -e "$want" || fail "missing /$want/ in:
$out"
done
printf '%s\n' "$out" | grep -q 'off {' && fail "a disabled inbound was written"
# defaults stay out of the file
s1=$(printf '%s\n' "$out" | sed -n '/^    s1 {/,/^    }/p')
printf '%s\n' "$s1" | grep -Eq 'udp|sniff|resolve|username' && fail "defaults were written for s1: $s1"

# --- invalid input stops the write and leaves the old file
for bad in "name=bad name" "name=" "name=$(printf 'a%.0s' $(seq 1 33))"; do
	reset
	printf 'old\n' > "$tmp/local.dae"
	cat > "$tmp/uci" <<UCI
dae.@inbound[0]=inbound
dae.@inbound[0].$bad
dae.@inbound[0].listen=127.0.0.1:1080
UCI
	if run; then
		# an entirely empty section is skipped; a name is required otherwise
		[ "$bad" = "name=" ] || fail "invalid inbound '$bad' was accepted"
	fi
done

reset
printf 'old\n' > "$tmp/local.dae"
cat > "$tmp/uci" <<'UCI'
dae.@inbound[0]=inbound
dae.@inbound[0].name=ok
dae.@inbound[0].listen=127.0.0.1:1080
dae.@inbound[0].sniff=maybe
UCI
if run; then fail "an invalid sniff value was accepted"; fi
[ "$(cat "$tmp/local.dae")" = old ] || fail "local.dae was replaced by a failed write"

reset
cat > "$tmp/uci" <<'UCI'
dae.@inbound[0]=inbound
dae.@inbound[0].name=ok
UCI
if run; then fail "an inbound without listen was accepted"; fi

# --- a value with both quote kinds cannot be written
reset
cat > "$tmp/uci" <<'UCI'
dae.@inbound[0]=inbound
dae.@inbound[0].name=ok
dae.@inbound[0].listen=127.0.0.1:1080
dae.@inbound[0].username=u
dae.@inbound[0].password=a'b"c
UCI
if run; then fail "a password with both quote kinds was accepted"; fi

echo ok

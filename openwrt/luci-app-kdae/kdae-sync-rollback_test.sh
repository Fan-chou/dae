#!/bin/sh
# Filesystem-level rollback helpers used by kdae-sync.sh.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SCRIPT="$ROOT/root/usr/libexec/dae/kdae-sync.sh"

KDAE_SYNC_SOURCE=1
# shellcheck disable=SC1090
. "$SCRIPT"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# restore_regular: bak (pre-write snapshot) replaces dest
printf 'new-local\n' > "$tmp/local.dae"
printf 'old-local\n' > "$tmp/local.dae.bak"
restore_regular "$tmp/local.dae" "$tmp/local.dae.bak"
got=$(cat "$tmp/local.dae")
[ "$got" = "old-local" ] || fail "restore_regular with bak got $got"
[ ! -f "$tmp/local.dae.bak" ] || fail "bak should be consumed by mv"

# restore_regular: no bak removes dest
printf 'orphan\n' > "$tmp/orphan.dae"
restore_regular "$tmp/orphan.dae" ""
[ ! -f "$tmp/orphan.dae" ] || fail "restore_regular without bak should remove dest"

# first publication: empty old_current drops current/ and generated symlink
mkdir -p "$tmp/first/generations/gen-new/generated"
ln -sfn generations/gen-new "$tmp/first/current"
ln -sfn current/generated "$tmp/first/generated"
restore_generation_current "$tmp/first" ""
[ ! -e "$tmp/first/current" ] || fail "first publish rollback left current/"
[ ! -e "$tmp/first/generated" ] || fail "first publish rollback left generated"
[ -d "$tmp/first/generations/gen-new" ] || fail "generation dir should remain on disk"

# subsequent publication: restore pre-sync current
mkdir -p "$tmp/next/generations/gen-old/generated" "$tmp/next/generations/gen-new/generated"
ln -sfn generations/gen-new "$tmp/next/current"
ln -sfn current/generated "$tmp/next/generated"
restore_generation_current "$tmp/next" "generations/gen-old"
tgt=$(readlink "$tmp/next/current")
[ "$tgt" = "generations/gen-old" ] || fail "current restored to $tgt"
gen=$(readlink "$tmp/next/generated")
[ "$gen" = "current/generated" ] || fail "generated retargeted to $gen"

echo "ok"

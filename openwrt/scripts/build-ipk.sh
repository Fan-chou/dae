#!/bin/sh
# Build ImmortalWrt 24.10 x86_64 ipk files without the full SDK.
# Usage: openwrt/scripts/build-ipk.sh [output-dir]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$ROOT/build/openwrt-feed"}
ARCH=x86_64
if [ -n "${KDAE_VERSION:-}" ]; then
	VERSION=$KDAE_VERSION
else
	date=$(git -C "$ROOT" log -1 --format='%cd' --date=short | tr -d '-')
	count=$(git -C "$ROOT" rev-list --count HEAD)
	commit=$(git -C "$ROOT" rev-parse --short HEAD)
	VERSION="${date}.r${count}.${commit}"
fi
RELEASE=1
PKGVER="${VERSION}-${RELEASE}"

export GOROOT=${GOROOT:-/root/sdk/go1.26.0}
export PATH="$GOROOT/bin:$PATH"
export GOTOOLCHAIN=${GOTOOLCHAIN:-local}
export GOMODCACHE=${GOMODCACHE:-/root/go-mod}
export GOTMPDIR=${GOTMPDIR:-/root/go-tmp}
export GOCACHE=${GOCACHE:-/root/go-cache}
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

mkdir -p "$GOTMPDIR" "$GOCACHE" "$OUT"
export TMPDIR="$ROOT/build/tmp"
mkdir -p "$TMPDIR"
cd "$ROOT"

echo ">> building dae and dae-rule-sync ($VERSION)"
: > /tmp/kdae-empty-build-tags
make dae OUTPUT="$ROOT/build/dae" BUILD_TAGS_FILE=/tmp/kdae-empty-build-tags
make dae-rule-sync RULE_SYNC_OUTPUT="$ROOT/build/dae-rule-sync"

pack_ipk() {
	pkg=$1
	pkgarch=$2
	control=$3
	datadir=$4
	workdir=$(mktemp -d)
	mkdir -p "$workdir/control" "$workdir/data"
	printf '%s\n' "$control" | sed '/^$/d' > "$workdir/control/control"
	if [ -n "${5:-}" ]; then
		printf '%s\n' "$5" > "$workdir/control/postinst"
		chmod 0755 "$workdir/control/postinst"
	fi
	if [ -n "${6:-}" ]; then
		printf '%s\n' "$6" > "$workdir/control/prerm"
		chmod 0755 "$workdir/control/prerm"
	fi
	cp -a "$datadir"/. "$workdir/data/"
	installed=$(find "$workdir/data" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')
	tmpctl=$(mktemp)
	awk -v size="$installed" '
		BEGIN { done=0 }
		/^Installed-Size:/ { print "Installed-Size: " size; done=1; next }
		{ print }
		END { if (!done) print "Installed-Size: " size }
	' "$workdir/control/control" > "$tmpctl"
	mv "$tmpctl" "$workdir/control/control"
	printf '2.0\n' > "$workdir/debian-binary"
	(cd "$workdir/control" && tar --format=ustar --numeric-owner --owner=0 --group=0 -czf "$workdir/control.tar.gz" .)
	(cd "$workdir/data" && tar --format=ustar --numeric-owner --owner=0 --group=0 -czf "$workdir/data.tar.gz" .)
	# ImmortalWrt 24.10 opkg expects a gzipped tar (not a Debian ar archive).
	ipk="$OUT/${pkg}_${PKGVER}_${pkgarch}.ipk"
	rm -f "$ipk"
	(cd "$workdir" && tar --format=ustar --numeric-owner --owner=0 --group=0 -czf "$ipk" debian-binary data.tar.gz control.tar.gz)
	rm -rf "$workdir"
	echo "built $ipk"
}

# --- kdae ---
kdae_data=$(mktemp -d)
mkdir -p "$kdae_data/usr/bin" "$kdae_data/etc/init.d" "$kdae_data/etc/config" \
	"$kdae_data/etc/dae" "$kdae_data/lib/upgrade/keep.d" "$kdae_data/usr/libexec/dae"
install -m 0755 "$ROOT/build/dae" "$kdae_data/usr/bin/dae"
install -m 0755 "$ROOT/openwrt/kdae/files/dae.init" "$kdae_data/etc/init.d/dae"
install -m 0755 "$ROOT/openwrt/kdae/files/kdae-recover.sh" "$kdae_data/usr/libexec/dae/kdae-recover.sh"
install -m 0644 "$ROOT/openwrt/kdae/files/dae.config" "$kdae_data/etc/config/dae"
install -m 0644 "$ROOT/example.dae" "$kdae_data/etc/dae/example.dae"
install -m 0644 "$ROOT/openwrt/kdae/files/dae.keep" "$kdae_data/lib/upgrade/keep.d/dae"
dae_uci_md5=$(md5sum "$kdae_data/etc/config/dae" | awk '{print $1}')
pack_ipk kdae "$ARCH" "Package: kdae
Version: $PKGVER
Depends: libc, ca-bundle, kmod-sched-core, kmod-sched-bpf, kmod-xdp-sockets-diag, kmod-veth
Provides: dae
Conflicts: dae
Replaces: dae
Section: net
Architecture: $ARCH
Maintainer: kdae local feed
Description: kdae eBPF transparent proxy (installs as /usr/bin/dae). Sockmap off by default.
Conffiles:
 /etc/config/dae $dae_uci_md5
" "$kdae_data"
rm -rf "$kdae_data"

# --- kdae-rule-sync ---
sync_data=$(mktemp -d)
mkdir -p "$sync_data/usr/libexec/dae"
install -m 0755 "$ROOT/build/dae-rule-sync" "$sync_data/usr/libexec/dae/dae-rule-sync"
pack_ipk kdae-rule-sync "$ARCH" "Package: kdae-rule-sync
Version: $PKGVER
Depends: libc, kdae
Section: net
Architecture: $ARCH
Maintainer: kdae local feed
Description: Mihomo-to-kdae generation publisher.
" "$sync_data"
rm -rf "$sync_data"

# --- luci-app-kdae ---
luci_data=$(mktemp -d)
mkdir -p "$luci_data/usr/share/luci/menu.d" \
	"$luci_data/usr/share/rpcd/acl.d" \
	"$luci_data/www/luci-static/resources/view/kdae" \
	"$luci_data/usr/libexec/dae"
install -m 0644 "$ROOT/openwrt/luci-app-kdae/root/usr/share/luci/menu.d/luci-app-kdae.json" \
	"$luci_data/usr/share/luci/menu.d/"
install -m 0644 "$ROOT/openwrt/luci-app-kdae/root/usr/share/rpcd/acl.d/luci-app-kdae.json" \
	"$luci_data/usr/share/rpcd/acl.d/"
install -m 0644 "$ROOT/openwrt/luci-app-kdae/htdocs/luci-static/resources/view/kdae/"*.js \
	"$luci_data/www/luci-static/resources/view/kdae/"
install -m 0755 "$ROOT/openwrt/luci-app-kdae/root/usr/libexec/dae/kdae-sync.sh" \
	"$luci_data/usr/libexec/dae/kdae-sync.sh"
install -m 0755 "$ROOT/openwrt/luci-app-kdae/root/usr/libexec/dae/kdae-write-local.sh" \
	"$luci_data/usr/libexec/dae/kdae-write-local.sh"
install -m 0755 "$ROOT/openwrt/luci-app-kdae/root/usr/libexec/dae/kdae-list-nodes.sh" \
	"$luci_data/usr/libexec/dae/kdae-list-nodes.sh"
pack_ipk luci-app-kdae all "Package: luci-app-kdae
Version: $PKGVER
Depends: libc, kdae
Conflicts: luci-app-dae
Section: luci
Architecture: all
Maintainer: kdae local feed
Description: LuCI for kdae start/stop/restart, crash recover, validate, reload, and rule-sync.
" "$luci_data"
rm -rf "$luci_data"

# --- kdae-ui ---
echo ">> building kdae-ui"
PNPM=${PNPM:-pnpm}
if ! command -v "$PNPM" >/dev/null 2>&1; then
	echo "pnpm is required to build kdae-ui (set PNPM=... if it is not on PATH)" >&2
	exit 1
fi
(cd "$ROOT/web" && "$PNPM" build)
ui_data=$(mktemp -d)
mkdir -p "$ui_data/www/kdae-ui/assets" "$ui_data/www/cgi-bin"
install -m 0644 "$ROOT/web/dist/index.html" "$ui_data/www/kdae-ui/"
cp -a "$ROOT/web/dist/assets/." "$ui_data/www/kdae-ui/assets/"
install -m 0755 "$ROOT/openwrt/kdae-ui/files/kdae-proxy.cgi" "$ui_data/www/cgi-bin/kdae-proxy"
if [ -e "$ui_data/www/kdae-ui/vue.global.prod.js" ] || [ -e "$ui_data/www/kdae-ui/app.js" ]; then
	echo "kdae-ui ipk must not ship vue.global.prod.js or app.js" >&2
	rm -rf "$ui_data"
	exit 1
fi
if ! grep -q '/kdae-ui/assets/' "$ui_data/www/kdae-ui/index.html"; then
	echo "kdae-ui index.html is missing hashed Vite assets" >&2
	rm -rf "$ui_data"
	exit 1
fi
pack_ipk kdae-ui all "Package: kdae-ui
Version: $PKGVER
Depends: libc
Section: net
Architecture: all
Maintainer: kdae local feed
Description: Vue panel for kdae /v1 (not Clash-compatible).
" "$ui_data"
rm -rf "$ui_data"

# Packages index (unsigned until publish-feed.sh signs on the router)
(
	cd "$OUT"
	rm -f Packages Packages.gz
	for ipk in *.ipk; do
		[ -f "$ipk" ] || continue
		workdir=$(mktemp -d)
		(cd "$workdir" && tar -xzf "$OUT/$ipk" control.tar.gz && tar -xzf control.tar.gz ./control)
		size=$(wc -c < "$ipk")
		sha256=$(sha256sum "$ipk" | awk '{print $1}')
		{
			grep -v '^$' "$workdir/control"
			echo "Filename: $ipk"
			echo "Size: $size"
			echo "SHA256sum: $sha256"
			echo
		}
		rm -rf "$workdir"
	done > Packages
	gzip -9c Packages > Packages.gz
)

echo ">> feed files in $OUT"
ls -l "$OUT"

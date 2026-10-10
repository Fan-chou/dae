#!/bin/sh
# Package fdae for OpenWrt without the SDK: one ipk and one apk per
# architecture, plus an arch-independent luci-app-fdae of each.
#
#   FDAE_UI=web-next/dist \
#   FDAE_BIN_x86_64=build/dae-amd64 FDAE_BIN_aarch64=build/dae-arm64 \
#   openwrt/build.sh [outdir]
#
# A missing FDAE_BIN_<arch> skips that architecture. FDAE_VERSION overrides the
# version; FDAE_NO_APK=1 skips the apk files (they need docker, see below).
set -eu

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
OUT=${1:-"$ROOT/build/openwrt"}
UI=${FDAE_UI:-"$ROOT/web-next/dist"}
mkdir -p "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)

if [ -n "${FDAE_VERSION:-}" ]; then
	VERSION=$FDAE_VERSION
else
	VERSION="$(git -C "$ROOT" log -1 --format=%cd --date=format:%Y%m%d).$(git -C "$ROOT" rev-list --count HEAD)"
fi
DEPENDS="libc ca-bundle kmod-sched-core kmod-sched-bpf kmod-xdp-sockets-diag kmod-veth"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# stage_fdae <dir> <binary>
stage_fdae() {
	d=$1
	mkdir -p "$d/usr/bin" "$d/etc/init.d" "$d/etc/config" "$d/etc/dae" \
		"$d/usr/libexec/fdae" "$d/usr/share/fdae-ui" "$d/lib/upgrade/keep.d"
	install -m 0755 "$2" "$d/usr/bin/dae"
	install -m 0755 "$HERE/fdae/files/dae.init" "$d/etc/init.d/dae"
	install -m 0644 "$HERE/fdae/files/dae.config" "$d/etc/config/dae"
	install -m 0600 "$HERE/fdae/files/config.dae" "$d/etc/dae/config.dae"
	for f in apply write-local recover; do
		install -m 0755 "$HERE/fdae/files/$f.sh" "$d/usr/libexec/fdae/$f.sh"
	done
	cp -R "$UI"/. "$d/usr/share/fdae-ui/"
	printf '/etc/dae/\n/etc/config/dae\n/usr/libexec/fdae/dae.prev\n' > "$d/lib/upgrade/keep.d/fdae"
}

stage_luci() {
	d=$1
	mkdir -p "$d/www"
	cp -R "$HERE/luci-app-fdae/htdocs/." "$d/www/"
	cp -R "$HERE/luci-app-fdae/root/." "$d/"
}

# Nothing here starts or stops the service on install or upgrade: the new
# binary waits on disk until the switch button in LuCI moves dae onto it.
cat > "$WORK/luci.post" <<'S'
#!/bin/sh
rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* 2>/dev/null
/etc/init.d/rpcd reload >/dev/null 2>&1 || true
exit 0
S
cat > "$WORK/fdae.prerm" <<'S'
#!/bin/sh
# Removing the package stops the service; upgrading does not.
[ "${PKG_UPGRADE:-0}" = 1 ] || /etc/init.d/dae stop >/dev/null 2>&1 || true
exit 0
S
cat > "$WORK/fdae.deinstall" <<'S'
#!/bin/sh
/etc/init.d/dae stop >/dev/null 2>&1 || true
exit 0
S

# ipk <name> <arch> <stagedir> <depends> <description> [prerm] [postinst]
ipk() {
	name=$1 arch=$2 stage=$3 deps=$4 desc=$5 prerm=${6:-} post=${7:-}
	w="$WORK/ipk-$name-$arch"
	mkdir -p "$w/control"
	size=$(du -sk "$stage" | cut -f1)
	{
		echo "Package: $name"
		echo "Version: $VERSION-1"
		echo "Architecture: $arch"
		echo "Maintainer: fdae"
		echo "Section: net"
		echo "Installed-Size: $((size * 1024))"
		[ -z "$deps" ] || echo "Depends: $(echo "$deps" | sed 's/ /, /g')"
		if [ "$name" = fdae ]; then
			echo "Provides: dae"
			echo "Replaces: kdae"
			echo "Conflicts: kdae"
		fi
		echo "Description: $desc"
	} > "$w/control/control"
	[ "$name" != fdae ] || printf '/etc/config/dae\n/etc/dae/config.dae\n' > "$w/control/conffiles"
	[ -z "$prerm" ] || install -m 0755 "$prerm" "$w/control/prerm"
	[ -z "$post" ] || install -m 0755 "$post" "$w/control/postinst"
	echo 2.0 > "$w/debian-binary"
	tar --owner=0 --group=0 --numeric-owner -C "$w/control" -czf "$w/control.tar.gz" .
	tar --owner=0 --group=0 --numeric-owner -C "$stage" -czf "$w/data.tar.gz" .
	tar --owner=0 --group=0 --numeric-owner -C "$w" -czf "$OUT/${name}_${VERSION}-1_${arch}.ipk" \
		./debian-binary ./control.tar.gz ./data.tar.gz
}

APKS=
# apk <name> <arch> <stagedir> <depends> <description> [pre-deinstall] [post]
# Collected here and made in one container run afterwards.
apk() {
	name=$1 arch=$2 stage=$3 deps=$4 desc=$5 pre=${6:-} post=${7:-}
	rel="apk-$name-$arch"
	mkdir -p "$WORK/$rel"
	[ -z "$pre" ] || cp "$pre" "$WORK/$rel/pre-deinstall"
	[ -z "$post" ] || { cp "$post" "$WORK/$rel/post-install"; cp "$post" "$WORK/$rel/post-upgrade"; }
	extra=
	[ "$name" != fdae ] || extra="--info provides:dae --info replaces:kdae"
	APKS="$APKS
$name|$arch|$stage|$deps|$desc|$extra"
}

make_apks() {
	[ -n "$APKS" ] || return 0
	[ "${FDAE_NO_APK:-0}" != 1 ] || return 0
	command -v docker >/dev/null 2>&1 || { echo "docker not found: skipping apk (FDAE_NO_APK=1 to silence)" >&2; return 0; }
	# apk-tools 3 (ADB v3) is what OpenWrt 25.12 uses and it is only packaged
	# in Alpine; mkpkg needs no network once it is installed.
	cat > "$WORK/mkapk.sh" <<'S'
set -eu
apk add -q apk-tools >/dev/null
chown -R 0:0 /work
while IFS='|' read -r name arch stage deps desc extra; do
	[ -n "$name" ] || continue
	rel=/work/apk-$name-$arch
	scripts=
	for s in pre-deinstall post-install post-upgrade; do
		[ ! -f "$rel/$s" ] || scripts="$scripts --script $s:$rel/$s"
	done
	# shellcheck disable=SC2086
	apk mkpkg --info "name:$name" --info "version:$VERSION-r1" --info "arch:$arch" \
		--info "description:$desc" --info "license:AGPL-3.0-only" --info "url:https://github.com/Fan-chou/dae" \
		--info "depends:$deps" $extra $scripts \
		--files "/work/stage-$name-$arch" --output "/out/$name-$VERSION-r1-$arch.apk"
done < /work/apks.list
S
	printf '%s\n' "$APKS" > "$WORK/apks.list"
	# stages are referenced by path inside the container
	docker run --rm ${FDAE_DOCKER_ARGS:-} -e VERSION="$VERSION" -v "$WORK:/work" -v "$OUT:/out" alpine:edge sh /work/mkapk.sh
}

built=0
for arch in x86_64 aarch64; do
	eval "bin=\${FDAE_BIN_$arch:-}"
	[ -n "$bin" ] || continue
	ipkarch=$arch
	[ "$arch" != aarch64 ] || ipkarch=aarch64_generic
	s="$WORK/stage-fdae-$arch"
	stage_fdae "$s" "$bin"
	desc="fdae: eBPF transparent proxy, installs as dae with its own panel"
	ipk fdae "$ipkarch" "$s" "$DEPENDS" "$desc" "$WORK/fdae.prerm"
	apk fdae "$arch" "$s" "$DEPENDS" "$desc" "$WORK/fdae.deinstall"
	built=1
done
[ "$built" = 1 ] || { echo "no FDAE_BIN_x86_64 / FDAE_BIN_aarch64 given" >&2; exit 1; }

s="$WORK/stage-luci-app-fdae-noarch"
stage_luci "$s"
desc="LuCI pages for fdae: settings, config, log, update switch"
ipk luci-app-fdae all "$s" "fdae luci-base" "$desc" "" "$WORK/luci.post"
apk luci-app-fdae noarch "$s" "fdae luci-base" "$desc" "" "$WORK/luci.post"

make_apks
( cd "$OUT" && sha256sum ./*.ipk ./*.apk 2>/dev/null > SHA256SUMS )
ls -la "$OUT"

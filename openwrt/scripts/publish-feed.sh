#!/bin/sh
# Publish ipk feed to ImmortalWrt 223:/www/kdae-feed and install the usign key.
# Usage: openwrt/scripts/publish-feed.sh [host] [feed-dir]
set -eu

HOST=${1:-root@192.168.124.223}
FEED_DIR=${2:-}
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
if [ -z "$FEED_DIR" ]; then
	FEED_DIR="$ROOT/build/openwrt-feed"
fi

ssh "$HOST" 'mkdir -p /www/kdae-feed /etc/opkg/keys /tmp/kdae-feed-keys'
if ! ssh "$HOST" 'test -f /etc/opkg/keys/kdae-feed.pub || test -n "$(ls /etc/opkg/keys 2>/dev/null)"'; then
	:
fi

# Generate usign keypair on the router once; keep the secret off this repo.
ssh "$HOST" 'if [ ! -f /root/kdae-feed-secret ]; then
	usign -G -s /root/kdae-feed-secret -p /root/kdae-feed.pub -c "kdae local feed"
	chmod 600 /root/kdae-feed-secret
	fp=$(usign -F -p /root/kdae-feed.pub)
	cp /root/kdae-feed.pub /etc/opkg/keys/$fp
	cp /root/kdae-feed.pub /www/kdae-feed/kdae-feed.pub
fi
fp=$(usign -F -p /root/kdae-feed.pub)
cp /root/kdae-feed.pub /etc/opkg/keys/$fp
cp /root/kdae-feed.pub /www/kdae-feed/kdae-feed.pub
echo $fp'

scp "$FEED_DIR"/*.ipk "$FEED_DIR"/Packages "$FEED_DIR"/Packages.gz "$HOST":/www/kdae-feed/

ssh "$HOST" 'cd /www/kdae-feed && usign -S -m Packages -s /root/kdae-feed-secret -x Packages.sig
grep -q "src/gz kdae file:///www/kdae-feed" /etc/opkg/customfeeds.conf 2>/dev/null || \
  echo "src/gz kdae file:///www/kdae-feed" >> /etc/opkg/customfeeds.conf
# Drop the HTTP feed line if a previous publish used 127.0.0.1 (uhttpd HTTPS breaks wget).
sed -i '/src\/gz kdae http:\/\/127.0.0.1\/kdae-feed/d' /etc/opkg/customfeeds.conf
opkg update
echo "feed ready: file:///www/kdae-feed"'

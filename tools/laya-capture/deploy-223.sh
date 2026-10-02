#!/bin/sh
# Install the reviewed passive evidence build with local rollback.
set -eu
umask 077
backup=/root/evidence-v1-20260926
[ ! -e "$backup" ] || { echo 'Backup already exists; refusing overwrite'; exit 1; }
[ "$(sha256sum /usr/bin/dae | cut -d ' ' -f 1)" = 6ad8948d24be1e3a2c0fd9d001536718dc2a7a8d0d51db2199bf678fc5441fa4 ]
[ "$(sha256sum /tmp/dae-passive-evidence-v1 | cut -d ' ' -f 1)" = 034fc69d28aa7d63a407736b866479a8b3853076b6525cadf9e4a410e84941ee ]
mkdir "$backup"
cp -p /usr/bin/dae "$backup/dae"
cp -p /etc/dae/config.dae "$backup/config.dae"
cp -p /etc/init.d/dae "$backup/init-dae"
cat > "$backup/rollback.sh" <<'ROLLBACK'
#!/bin/sh
set -eu
backup=/root/evidence-v1-20260926
cp "$backup/dae" /usr/bin/dae.rollback-new
chmod 755 /usr/bin/dae.rollback-new
mv /usr/bin/dae.rollback-new /usr/bin/dae
cp -p "$backup/config.dae" /etc/dae/config.dae
cp -p "$backup/init-dae" /etc/init.d/dae
/etc/init.d/dae restart
ROLLBACK
chmod 700 "$backup/rollback.sh"
changed=0
cleanup() {
 status=$?
 trap - 0 HUP INT TERM
 if [ "$changed" = 1 ]; then
  if sh "$backup/rollback.sh"; then
   echo 'Evidence deployment failed; rollback applied' >&2
  else
   echo 'Evidence deployment failed; rollback failed' >&2
  fi
 fi
 exit "$status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
[ "$(awk '/procd_append_param env GOMAXPROCS=2/ {n++} END {print n+0}' "$backup/init-dae")" = 1 ] || {
 echo 'Expected exactly one GOMAXPROCS env anchor; init script unchanged' >&2
 exit 1
}
sed '/^[[:space:]]*capture_group:/d' /etc/dae/config.dae > /etc/dae/.evidence-next.dae
/tmp/dae-passive-evidence-v1 validate -c /etc/dae/.evidence-next.dae
cp /tmp/dae-passive-evidence-v1 /usr/bin/dae.evidence-new
chmod 755 /usr/bin/dae.evidence-new
changed=1
sed '/procd_append_param env GOMAXPROCS=2/a\	procd_append_param env KDAE_EVIDENCE_KEY_FILE=/etc/dae/evidence-identity.key' "$backup/init-dae" > /etc/init.d/dae
grep -q 'procd_append_param env KDAE_EVIDENCE_KEY_FILE=/etc/dae/evidence-identity.key' /etc/init.d/dae
chmod 755 /etc/init.d/dae
mv /etc/dae/.evidence-next.dae /etc/dae/config.dae
mv /usr/bin/dae.evidence-new /usr/bin/dae
/etc/init.d/dae restart
for i in 1 2 3 4 5 6 7 8 9 10; do
 sleep 2
 if sh /usr/libexec/dae/read-observation.sh status 0 2>/dev/null | grep -q 'passive-evidence-v1-20260926'; then
  if sh /usr/libexec/dae/read-observation.sh evidence 0 2>/dev/null | grep -q '"enabled":true'; then
   echo 'Evidence deployment healthy'
   pidof dae
   changed=0
   exit 0
  fi
 fi
done
exit 1

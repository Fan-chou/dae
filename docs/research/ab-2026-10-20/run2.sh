#!/usr/bin/env bash
# Loopback-only A/B of two outbound pins. Everything lives under $W; all
# processes are killed on exit; no routes, firewall or services are touched.
#   usage: run2.sh check|perf
set -u
W=/root/ab2
cd "$W"
MODE=${1:-check}
UUID=11111111-2222-4333-8444-555555555555
SSKEY=AAECAwQFBgcICQoLDA0ODw==
CLIENT_CPUS=0-1     # client under test
SB_CPUS=4-7         # sing-box
IX_CPUS=8-9         # inner origin
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

mkdir -p run/t13 run/t12 run/plain results
(cd ixserver && go build -o ../run/ixserver .) || exit 1
taskset -c $IX_CPUS ./run/ixserver -mode tls13 -addr 127.0.0.1:18500 -udp 127.0.0.1:18501 -dir run/t13 >run/t13.log 2>&1 & PIDS+=($!)
taskset -c $IX_CPUS ./run/ixserver -mode tls12 -addr 127.0.0.1:18510 -udp 127.0.0.1:18511 -dir run/t12 >run/t12.log 2>&1 & PIDS+=($!)
taskset -c $IX_CPUS ./run/ixserver -mode plain -addr 127.0.0.1:18520 -udp 127.0.0.1:18521 -dir run/plain >run/plain.log 2>&1 & PIDS+=($!)
sleep 1

KP=$(sing-box generate reality-keypair)
RPRIV=$(echo "$KP" | awk '/PrivateKey/{print $2}')
RPUB=$(echo "$KP" | awk '/PublicKey/{print $2}')
RSID=0123456789abcdef
CERT=$W/run/t13/cert.pem; KEY=$W/run/t13/key.pem
cat > run/sb.json <<JSON
{"log":{"level":"warn"},
 "inbounds":[
  {"type":"vless","tag":"vision","listen":"127.0.0.1","listen_port":18443,
   "users":[{"name":"u","uuid":"$UUID","flow":"xtls-rprx-vision"}],
   "tls":{"enabled":true,"certificate_path":"$CERT","key_path":"$KEY"}},
  {"type":"vless","tag":"noflow","listen":"127.0.0.1","listen_port":18444,
   "users":[{"name":"u","uuid":"$UUID"}],
   "tls":{"enabled":true,"certificate_path":"$CERT","key_path":"$KEY"}},
  {"type":"hysteria2","tag":"hy2","listen":"127.0.0.1","listen_port":18600,
   "users":[{"name":"u","password":"abpass"}],
   "tls":{"enabled":true,"certificate_path":"$CERT","key_path":"$KEY","alpn":["h3"]}},
  {"type":"vmess","tag":"vmess","listen":"127.0.0.1","listen_port":18601,
   "users":[{"name":"u","uuid":"$UUID","alterId":0}]},
  {"type":"shadowsocks","tag":"ss2022","listen":"127.0.0.1","listen_port":18602,
   "method":"2022-blake3-aes-128-gcm","password":"$SSKEY"},
  {"type":"vless","tag":"reality","listen":"127.0.0.1","listen_port":18603,
   "users":[{"name":"u","uuid":"$UUID","flow":"xtls-rprx-vision"}],
   "tls":{"enabled":true,"server_name":"ab.example.test",
          "reality":{"enabled":true,"handshake":{"server":"127.0.0.1","server_port":18500},
                     "private_key":"$RPRIV","short_id":["$RSID"]}}},
  {"type":"socks","tag":"socks","listen":"127.0.0.1","listen_port":18650}
 ],
 "outbounds":[{"type":"direct","tag":"direct"}]}
JSON
sing-box check -c run/sb.json || { echo "sing-box config invalid"; exit 1; }
taskset -c $SB_CPUS sing-box run -c run/sb.json >run/sb.log 2>&1 & PIDS+=($!)

cat > run/xray.json <<JSON
{"log":{"loglevel":"warning"},
 "inbounds":[
  {"tag":"vision","listen":"127.0.0.1","port":18445,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID","flow":"xtls-rprx-vision"}],"decryption":"none"},
   "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"$CERT","keyFile":"$KEY"}]}}}],
 "outbounds":[{"protocol":"freedom"}]}
JSON
if [ "$MODE" = check ]; then
  ./xray/xray run -test -c run/xray.json >/dev/null || { echo "xray config invalid"; exit 1; }
  taskset -c $SB_CPUS ./xray/xray run -c run/xray.json >run/xray.log 2>&1 & PIDS+=($!)
fi
sleep 3
for p in 18443 18444 18445 18500 18510 18520 18601 18602 18603 18650; do
  [ "$MODE" != check ] && [ $p = 18445 ] && continue
  (echo > /dev/tcp/127.0.0.1/$p) 2>/dev/null || { echo "port $p not up"; tail -5 run/sb.log; exit 1; }
done

# kind -> port, chain port, inner (tls13 target port)
cell_env() { # echo "PORT CHAIN"
  case $1 in
    vision) echo "18443 -";; vision-xray) echo "18445 -";; vision-noflow) echo "18444 -";;
    vmess) echo "18601 -";; ss2022) echo "18602 -";; hy2) echo "18600 -";;
    hy2hop) echo "18600 18650";; reality) echo "18603 -";; direct) echo "0 -";;
  esac
}
run_one() { # pin kind inner tests...   -> stdout: test output
  local pin=$1 kind=$2 inner=$3; shift 3
  local real=$kind; [ $kind = vision-xray ] && real=vision
  set -- $(cell_env $kind) "$@"; local port=$1 chain=$2; shift 2
  local tport=18500 uport=18501
  [ $inner = tls12 ] && { tport=18510; uport=18511; }
  [ $inner = plain ] && { tport=18520; uport=18521; }
  local ch=""; [ $chain != - ] && ch=$chain
  AB_KIND=$real AB_PORT=$port AB_CHAIN_PORT=$ch AB_INNER=$inner AB_TARGET=127.0.0.1:$tport AB_UDP=127.0.0.1:$uport \
  AB_REALITY_PUB=$RPUB AB_REALITY_SID=$RSID GOMAXPROCS=2 \
  taskset -c $CLIENT_CPUS ./bin/ab.$pin -test.v -test.count=1 -test.timeout=600s -test.run "$1" 2>&1
}

if [ "$MODE" = check ]; then
  : > results/check.${CHECK_TAG:-csv}
  for kind in ${CHECK_KINDS:-vision vision-xray vision-noflow vmess ss2022 hy2 hy2hop reality}; do
    for inner in tls13 tls12 plain; do
      # inner variants only matter for the TLS/Vision family; the rest run tls13 once
      case $kind in vision|vision-xray) ;; *) [ $inner != tls13 ] && continue;; esac
      for pin in old new; do
        out=$(run_one $pin $kind $inner 'TestAB(Download|Upload|ManyConns|UDP)$')
        echo "$out" > "run/chk-$kind-$pin-$inner.log"
        for c in download upload manyconns udp; do
          line=$(echo "$out" | grep "^ABCHK kind=.* case=$c " | tail -1)
          [ -z "$line" ] && line="case=$c ok=0 fail=NA(no-result)"
          echo "$kind|$inner|$pin|$(echo "$line" | grep -o "case=.*")" >> results/check.${CHECK_TAG:-csv}
        done
      done
    done
  done
  echo CHECK_DONE
fi

if [ "$MODE" = perf ]; then
  : > results/perf.csv
  KINDS="direct vision vmess ss2022 hy2 reality"
  TESTS='TestABPerf(Tput1|Up1|Tput8|TTFB|RTT|UDP)$'
  for rep in 0 1 2 3 4 5; do
    for kind in $KINDS; do
      if [ $((rep % 2)) -eq 0 ]; then order="old new"; else order="new old"; fi
      for pin in $order; do
        for t in Tput1 Up1 Tput8 TTFB RTT UDP; do
          out=$(run_one $pin $kind tls13 "TestABPerf$t\$")
          echo "$out" > "run/perf-$kind-$pin-$t-$rep.log"
          echo "$out" | grep '^ABRES' | sed -E "s/^ABRES kind=([^ ]+) metric=([^ ]+) value=([^ ]+) unit=(.*)$/$rep,\1,$pin,\2,\3,\4/" >> results/perf.csv
          echo "$out" | grep -q '^FAIL\|^--- FAIL\|panic:' && echo "$rep,$kind,$pin,$t,FAILED," >> results/perf.csv
        done
      done
    done
    echo "rep $rep done $(date +%T)"
  done
  echo PERF_DONE
fi

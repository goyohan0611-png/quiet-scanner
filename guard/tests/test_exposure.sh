#!/usr/bin/env bash
# Actual host listeners, independent network namespace, TCP firewall outcomes,
# IPv4/IPv6 and inspector lifecycle in a disposable Ubuntu VM.
set -euo pipefail
test "${QUIET_GUARD_DISPOSABLE_VM:-}" = YES
test "$(id -u)" = 0
binary=$(realpath "${1:?compiled binary}")
root=$(realpath "$(dirname "$0")/..")
temporary=$(mktemp -d)
cleanup() {
  if [[ -s "$temporary/fixture.pid" ]]; then kill "$(cat "$temporary/fixture.pid")" 2>/dev/null || true; fi
  ip netns delete qg-exposure-client 2>/dev/null || true
  ip link delete qg-exposure-host 2>/dev/null || true
  nft delete table inet quiet_guard_exposure_test 2>/dev/null || true
  rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'echo "Exposure failure at line $LINENO"; journalctl -u quiet-guard-exposure.service --no-pager -n 35 || true; cat /var/lib/quiet-guard/exposure/report.json 2>/dev/null || true' ERR
umask 077
openssl genpkey -algorithm ED25519 -out "$temporary/private.pem"
openssl pkey -in "$temporary/private.pem" -pubout -out "$temporary/public.pem"
bash "$root/scripts/package.sh" "$binary" "$temporary/release" 1 0.1.0 "$temporary/private.pem"
python3 "$root/scripts/deploy.py" install --bundle "$temporary/release" --trusted-key "$temporary/public.pem"
ip netns add qg-exposure-client
ip link add qg-exposure-host type veth peer name qg-exposure-peer
ip link set qg-exposure-peer netns qg-exposure-client
ip addr add 10.205.0.1/24 dev qg-exposure-host
ip -6 addr add fd205::1/64 dev qg-exposure-host nodad
ip link set qg-exposure-host up
ip -n qg-exposure-client addr add 10.205.0.2/24 dev qg-exposure-peer
ip -n qg-exposure-client -6 addr add fd205::2/64 dev qg-exposure-peer nodad
ip -n qg-exposure-client link set lo up
ip -n qg-exposure-client link set qg-exposure-peer up
python3 - "$temporary/fixture.ready" <<'PY' &
import socket,select,sys,pathlib
sockets=[]
for family,address,port,kind in [(socket.AF_INET,'0.0.0.0',5432,socket.SOCK_STREAM),(socket.AF_INET,'127.0.0.1',6379,socket.SOCK_STREAM),(socket.AF_INET,'0.0.0.0',18081,socket.SOCK_STREAM),(socket.AF_INET6,'::',18082,socket.SOCK_STREAM),(socket.AF_INET6,'::1',6543,socket.SOCK_STREAM),(socket.AF_INET,'0.0.0.0',19999,socket.SOCK_DGRAM)]:
 s=socket.socket(family,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((address,port))
 if kind==socket.SOCK_STREAM:s.listen(32)
 sockets.append(s)
pathlib.Path(sys.argv[1]).touch()
while True:
 for s in select.select(sockets,[],[],1)[0]:
  if s.type==socket.SOCK_STREAM:
   connection,_=s.accept();connection.settimeout(0.5)
   try:assert connection.recv(1)==b'', 'Probe sent application data'
   except socket.timeout:pass
   connection.close()
  else:raise RuntimeError('Inspector sent a UDP datagram')
PY
echo "$!" > "$temporary/fixture.pid"
for attempt in $(seq 1 30); do test -f "$temporary/fixture.ready" && break; sleep 0.1; done
nft -f - <<'NFT'
table inet quiet_guard_exposure_test {
 chain input { type filter hook input priority -5; policy accept; tcp dport 18081 drop; }
}
NFT
nft -s -j list ruleset > "$temporary/firewall-before.json"
quiet-guard exposure enable
systemctl is-enabled --quiet quiet-guard-exposure.timer
quiet-guard exposure check > "$temporary/local.json"
runuser -u nobody -- quiet-guard exposure status > "$temporary/public-status.json"
python3 - "$temporary/local.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));s=r['inventory']['listeners']
assert any(x['port']==5432 and x['address']=='0.0.0.0' and x['owners'] for x in s)
assert any(x['port']==6379 and x['address']=='127.0.0.1' for x in s)
assert any(x['port']==18082 and x['address']=='::' for x in s)
assert any(x['port']==6543 and x['address']=='::1' for x in s)
assert any(x['port']==19999 and x['transport']=='udp' for x in s)
assert any(x['port']==5432 and x['evidence']=='non_loopback_bind_only' and x['category']=='unidentified_process' for x in r['findings'])
assert not any(x['port']==6379 for x in r['findings'])
assert r['risk']=='attention' and r['external'] is None
PY
echo 'PASS: real TCP/UDP and IPv4/IPv6 bindings inventoried; process metadata collected without treating a port number as service identity'
quiet-guard exposure prepare --target 10.205.0.1 --ports 5432,6379,18081,18083 > "$temporary/request.json"
if quiet-guard exposure probe "$temporary/request.json" > "$temporary/local-probe.json"; then echo 'Accepted a local probe as external evidence'; exit 1; fi
ip netns exec qg-exposure-client "$binary" exposure probe "$temporary/request.json" > "$temporary/result.json"
python3 - "$temporary/result.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));a={x['port']:x['outcome'] for x in r['attempts']}
assert r['source']=='10.205.0.2' and a[5432]=='connected' and a[6379]=='refused' and a[18081]=='timed_out' and a[18083]=='refused',r
PY
quiet-guard exposure import "$temporary/result.json"
if quiet-guard exposure import "$temporary/result.json"; then echo 'Accepted a consumed request'; exit 1; fi
quiet-guard exposure check > "$temporary/merged.json"
python3 - "$temporary/merged.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['external'] and r['risk']!='safe'
assert any(x['port']==5432 and x['evidence']=='connected_from_one_operator_probe' for x in r['findings'])
assert not any(x['port']==18083 for x in r['findings'])
assert any('operator-supplied' in x for x in r['limitations'])
PY
echo 'PASS: real external-peer connection, refusal and firewall timeout distinguished; local probes and replay rejected; failed connections never mean safe'
quiet-guard exposure prepare --target fd205::1 --ports 18082,6543 > "$temporary/request6.json"
ip netns exec qg-exposure-client "$binary" exposure probe "$temporary/request6.json" > "$temporary/result6.json"
quiet-guard exposure import "$temporary/result6.json"
python3 - "$temporary/result6.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));a={x['port']:x['outcome'] for x in r['attempts']}
assert r['source']=='fd205::2' and a[18082]=='connected' and a[6543]=='refused',r
PY
echo 'PASS: actual IPv6 TCP probe and IPv6 loopback-only binding tested separately from IPv4'
# A different host/socket snapshot must invalidate otherwise matching evidence.
quiet-guard exposure prepare --target 10.205.0.1 --ports 5432 > "$temporary/stale-request.json"
ip netns exec qg-exposure-client "$binary" exposure probe "$temporary/stale-request.json" > "$temporary/stale-result.json"
kill "$(cat "$temporary/fixture.pid")"
wait "$(cat "$temporary/fixture.pid")" 2>/dev/null || true
if quiet-guard exposure import "$temporary/stale-result.json"; then echo 'Accepted results after listener removal'; exit 1; fi
quiet-guard exposure check > "$temporary/changed.json"
python3 - "$temporary/changed.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['external'] is None
assert not any(x['port']==5432 for x in r['inventory']['listeners'])
PY
systemctl stop quiet-guard-exposure.timer
python3 - <<'PY'
import json,pathlib,time
p=pathlib.Path('/var/lib/quiet-guard/exposure/report.json');r=json.loads(p.read_text());r['boot_seconds']=max(0,int(time.clock_gettime(time.CLOCK_BOOTTIME))-91);p.write_text(json.dumps(r))
PY
quiet-guard exposure status | python3 -c 'import json,sys;assert json.load(sys.stdin)["state"]=="unknown"'
quiet-guard exposure check > /dev/null
cp /etc/systemd/system/quiet-guard-exposure.service "$temporary/owned-unit"
printf '\n# operator change\n' >> /etc/systemd/system/quiet-guard-exposure.service
if quiet-guard exposure remove; then exit 1; fi
grep -q 'operator change' /etc/systemd/system/quiet-guard-exposure.service
cp "$temporary/owned-unit" /etc/systemd/system/quiet-guard-exposure.service
quiet-guard exposure disable
quiet-guard exposure status | python3 -c 'import json,sys;assert json.load(sys.stdin)["state"]=="off"'
quiet-guard exposure enable
quiet-guard exposure remove
test ! -e /etc/quiet-guard/exposure
test ! -e /var/lib/quiet-guard/exposure
test ! -e /etc/systemd/system/quiet-guard-exposure.service
quiet-guard exposure enable
quiet-guard exposure remove
nft -s -j list ruleset > "$temporary/firewall-after.json"
cmp "$temporary/firewall-before.json" "$temporary/firewall-after.json"
python3 "$root/scripts/deploy.py" uninstall
echo 'PASS: changed bindings and expired inventory invalidate evidence; operator edits preserved; disable/remove/reinstall succeed; firewall rules remain byte-identical'

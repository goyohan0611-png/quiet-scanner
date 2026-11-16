#!/usr/bin/env bash
# Actual systemd, journald, CrowdSec API and nftables in a disposable Ubuntu VM.
set -euo pipefail
test "${QUIET_GUARD_DISPOSABLE_VM:-}" = YES
test "$(id -u)" = 0
binary=$(realpath "${1:?compiled binary}")
root=$(realpath "$(dirname "$0")/..")
temporary=$(mktemp -d)
cleanup() {
  if [[ -e /usr/bin/crowdsec.qg-test-original ]]; then mv /usr/bin/crowdsec.qg-test-original /usr/bin/crowdsec; fi
  ip netns delete qg-ssh-client 2>/dev/null || true
  ip link delete qg-ssh-host 2>/dev/null || true
  if [[ -s "$temporary/listener.pid" ]]; then kill "$(cat "$temporary/listener.pid")" 2>/dev/null || true; fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'journalctl -u quiet-guard-ssh-engine -u quiet-guard-ssh-enforcer --no-pager -n 60 || true; cat /run/quiet-guard-ssh/health.json 2>/dev/null || true' ERR
umask 077
apt-get update -qq
apt-get install -y --no-install-recommends nftables openssh-server openssh-client iproute2
systemctl start ssh.socket || systemctl start ssh.service
openssl genpkey -algorithm ED25519 -out "$temporary/private.pem"
openssl pkey -in "$temporary/private.pem" -pubout -out "$temporary/public.pem"
bash "$root/scripts/package.sh" "$binary" "$temporary/release" 1 0.1.0 "$temporary/private.pem"
python3 "$root/scripts/deploy.py" install --bundle "$temporary/release" --trusted-key "$temporary/public.pem"
cs() { /usr/bin/cscli -c /etc/quiet-guard/ssh/config.yaml "$@"; }
wait_for() {
  local limit=$((SECONDS + 35))
  while ! "$@"; do
    if (( SECONDS >= limit )); then echo "Timed out waiting for $*" >&2; return 1; fi
    sleep 1
  done
}
has_ban() { nft -j list set inet quiet_guard_ssh banned4 | python3 -c 'import json,sys;v=json.load(sys.stdin);assert any(e["elem"]["val"]==sys.argv[1] for r in v["nftables"] for e in r.get("set",{}).get("elem",[]))' "$1" 2>/dev/null; }
unknown() { python3 -c 'import json;assert json.load(open("/run/quiet-guard-ssh/health.json"))["phase"]=="unknown"' 2>/dev/null; }
connect() {
  ip netns exec qg-ssh-client python3 - "$1" "$2" <<'PY'
import socket,sys
with socket.socket() as s:
 s.settimeout(1);s.bind((sys.argv[1],0));s.connect(('10.203.0.1',int(sys.argv[2])))
PY
}
ip netns add qg-ssh-client
ip link add qg-ssh-host type veth peer name qg-ssh-peer
ip link set qg-ssh-peer netns qg-ssh-client
ip addr add 10.203.0.1/24 dev qg-ssh-host
ip link set qg-ssh-host up
ip -n qg-ssh-client addr add 10.203.0.2/24 dev qg-ssh-peer
ip -n qg-ssh-client addr add 10.203.0.3/24 dev qg-ssh-peer
ip -n qg-ssh-client link set lo up
ip -n qg-ssh-client link set qg-ssh-peer up
python3 - <<'PY' &
import socket
s=socket.socket();s.bind(('10.203.0.1',18080));s.listen()
while True:
 c,_=s.accept();c.close()
PY
echo "$!" > "$temporary/listener.pid"
sleep 1
connect 10.203.0.2 22
connect 10.203.0.2 18080
nft add table inet quiet_guard_test_sentinel
nft add table inet quiet_guard_ssh
if quiet-guard ssh enable --direct --management-ip 10.203.0.3; then exit 1; fi
nft list table inet quiet_guard_ssh >/dev/null
nft delete table inet quiet_guard_ssh  # The test created this collision, not Guard.
test ! -e /usr/bin/crowdsec.qg-test-original
mv /usr/bin/crowdsec /usr/bin/crowdsec.qg-test-original
printf '#!/bin/sh\nexit 42\n' > /usr/bin/crowdsec
chmod 755 /usr/bin/crowdsec
if quiet-guard ssh enable --direct --management-ip 10.203.0.3; then exit 1; fi
mv /usr/bin/crowdsec.qg-test-original /usr/bin/crowdsec
test ! -e /etc/quiet-guard/ssh
test ! -e /var/lib/quiet-guard/ssh
test ! -e /etc/systemd/system/quiet-guard-ssh-engine.service
echo 'PASS: failed first SSH setup rolls back only its own files and can be retried'
quiet-guard ssh enable --direct --management-ip 10.203.0.3
systemctl is-enabled --quiet quiet-guard-ssh-engine quiet-guard-ssh-enforcer
quiet-guard ssh status
sleep 2  # Let the journald follower start before emitting real SSH failures.
for attempt in $(seq 1 10); do
  ip netns exec qg-ssh-client ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 -o PreferredAuthentications=none quietguard_invalid@10.203.0.1 true 2>/dev/null || true
done
wait_for has_ban 10.203.0.2
if connect 10.203.0.2 22; then echo 'Banned SSH connection succeeded' >&2; exit 1; fi
connect 10.203.0.2 18080
cs decisions list -o json > "$temporary/decisions.json"
python3 - "$temporary/decisions.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1]));assert any(d.get('value')=='10.203.0.2' and d.get('origin')=='crowdsec' for alert in v for d in alert.get('decisions',[])),v
PY
echo 'PASS: real failed SSH logins -> journald -> pinned parser/scenario -> local API -> verified SSH-only packet blocking; HTTP remains reachable'
cs decisions add -i 10.203.0.3 -d 10m >/dev/null
sleep 11
! has_ban 10.203.0.3
connect 10.203.0.3 22
quiet-guard ssh allow 10.203.0.2
! has_ban 10.203.0.2
connect 10.203.0.2 22
quiet-guard ssh remove-allow 10.203.0.2
wait_for has_ban 10.203.0.2
quiet-guard ssh unblock 10.203.0.2
! has_ban 10.203.0.2
connect 10.203.0.2 22
echo 'PASS: management IP remains reachable, SSH exceptions and manual unblock take effect'
cs decisions add -i 10.203.0.2 -d 10m >/dev/null
wait_for has_ban 10.203.0.2
systemctl restart quiet-guard-ssh-engine quiet-guard-ssh-enforcer
wait_for has_ban 10.203.0.2
systemctl is-enabled --quiet quiet-guard-ssh-engine quiet-guard-ssh-enforcer
systemctl stop quiet-guard-ssh-engine
wait_for unknown
sleep 46
connect 10.203.0.2 22
echo 'PASS: decisions survive service restart; engine failure removes verified state and stale bans expire'
quiet-guard ssh disable
! nft list table inet quiet_guard_ssh >/dev/null 2>&1
nft list table inet quiet_guard_test_sentinel >/dev/null
if python3 "$root/scripts/deploy.py" uninstall; then exit 1; fi
quiet-guard ssh enable
cp /etc/quiet-guard/ssh/rules/scenarios/ssh-bf.yaml "$temporary/original"
printf '\n# out-of-band edit\n' >> /etc/quiet-guard/ssh/rules/scenarios/ssh-bf.yaml
wait_for unknown
if quiet-guard ssh remove; then exit 1; fi
cp "$temporary/original" /etc/quiet-guard/ssh/rules/scenarios/ssh-bf.yaml
quiet-guard ssh remove
nft list table inet quiet_guard_test_sentinel >/dev/null
nft delete table inet quiet_guard_test_sentinel
python3 "$root/scripts/deploy.py" uninstall
echo 'PASS: OFF/remove preserve foreign firewall rules; edited configuration is preserved; active SSH integration blocks unsafe foundation uninstall'

#!/usr/bin/env bash
# Only for a disposable Linux CI VM. Uses real CrowdSec, systemd and nftables.
set -euo pipefail
test "$(id -u)" = 0
test "${QUIET_PROTECTION_DISPOSABLE_VM:-}" = YES || { echo 'Disposable VM opt-in required'; exit 2; }
GUARD=$(realpath "${1:?path to protection test binary}")
TEMP=$(mktemp -d)
HTTP_PID=
cleanup() {
  systemctl disable --now quiet-scanner-protection.service >/dev/null 2>&1 || true
  nft delete table ip quiet_scanner >/dev/null 2>&1 || true
  nft delete table ip6 quiet_scanner6 >/dev/null 2>&1 || true
  nft delete table inet qs_test_keep >/dev/null 2>&1 || true
  ip addr del 198.51.100.42/32 dev lo >/dev/null 2>&1 || true
  test -z "$HTTP_PID" || kill "$HTTP_PID" 2>/dev/null || true
}
trap cleanup EXIT
status() { "$GUARD" '{"operation":"status"}' > "$TEMP/status.json"; }
phase() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["phase"])' "$TEMP/status.json"; }
wait_phase() {
  local target=$1
  for _ in $(seq 1 35); do status; test "$(phase)" != "$target" || return 0; sleep 2; done
  cat "$TEMP/status.json"; journalctl -u quiet-scanner-protection.service --no-pager -n 30
  echo "Expected phase $target"; exit 1
}
# Leave unrelated rules in place throughout the entire test.
nft add table inet qs_test_keep
"$GUARD" '{"operation":"prepare"}' > "$TEMP/prepare.json"
test "$(stat -c %a /etc/quiet-scanner/protection/firewall.yaml)" = 600
"$GUARD" '{"operation":"enable"}' > "$TEMP/enable.json"
wait_phase on
python3 -c 'import json,sys;s=json.load(open(sys.argv[1]));assert s["protecting"] and all(s["checks"].values())' "$TEMP/status.json"
echo 'PASS: real engine API, bouncer pull, boot setting and both nftables DROP rules verified'

ip addr add 198.51.100.42/32 dev lo
python3 -m http.server 38563 --bind 127.0.0.1 --directory "$TEMP" >/dev/null 2>&1 & HTTP_PID=$!
sleep 1
curl --noproxy '*' --silent --fail --interface 198.51.100.42 --connect-timeout 2 http://127.0.0.1:38563/ >/dev/null
cscli decisions add --ip 198.51.100.42 --duration 5m >/dev/null
blocked=0
for _ in $(seq 1 20); do
  if ! curl --noproxy '*' --silent --fail --interface 198.51.100.42 --connect-timeout 2 http://127.0.0.1:38563/ >/dev/null; then blocked=1;break;fi
  sleep 1
done
test "$blocked" = 1 || { echo 'Real incoming traffic was not blocked';exit 1; }
echo 'PASS: real TCP request blocked after CrowdSec decision'
"$GUARD" '{"operation":"allow","ip":"198.51.100.42"}' > "$TEMP/allow.json"
python3 -c 'import json,sys;assert "198.51.100.42" in json.load(open(sys.argv[1]))["allowlist"]' "$TEMP/allow.json"
unblocked=0
for _ in $(seq 1 20); do
  if curl --noproxy '*' --silent --fail --interface 198.51.100.42 --connect-timeout 2 http://127.0.0.1:38563/ >/dev/null; then unblocked=1;break;fi
  sleep 1
done
test "$unblocked" = 1
"$GUARD" '{"operation":"remove_allow","ip":"198.51.100.42"}' > "$TEMP/remove-allow.json"
echo 'PASS: explicit exception removes real block and can be removed'

systemctl stop crowdsec.service
status
python3 -c 'import json,sys;assert not json.load(open(sys.argv[1]))["protecting"]' "$TEMP/status.json"
"$GUARD" '{"operation":"disable"}' > "$TEMP/disable.json"
wait_phase off
! nft list table ip quiet_scanner >/dev/null 2>&1
! nft list table ip6 quiet_scanner6 >/dev/null 2>&1
nft list table inet qs_test_keep >/dev/null
! systemctl is-enabled quiet-scanner-protection.service >/dev/null 2>&1
echo 'PASS: engine failure never reports protection; OFF removes only owned rules and boot setting'

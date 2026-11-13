#!/usr/bin/env bash
# A clean, disposable Ubuntu VM only. Exercises the exact embedded installer.
set -euo pipefail
test "$(id -u)" = 0
test "${QUIET_PROTECTION_DISPOSABLE_VM:-}" = YES
GUARD=$(realpath "${1:?test binary}")
diagnostics() {
  systemctl show quiet-scanner-protection-setup.service --property=ActiveState,Result,ExecMainStatus || true
  # Only this throwaway VM's fixed installer diagnostics, never config/key files.
  tail -n 16 /var/log/quiet-scanner-protection-setup.log 2>/dev/null | sed -E 's/(api_key:|password:|token:).*/\1 [redacted]/Ig' || true
}
trap diagnostics ERR
test ! -x /usr/bin/cscli
"$GUARD" '{"operation":"auto_enable"}' >/tmp/quiet-setup-initial.json
# Cancel immediately while apt is running: finish configuration safely, stay OFF.
"$GUARD" '{"operation":"disable"}' >/tmp/quiet-setup-cancel.json
for _ in $(seq 1 240); do
  "$GUARD" '{"operation":"status"}' >/tmp/quiet-setup-status.json
  phase=$(python3 -c 'import json;print(json.load(open("/tmp/quiet-setup-status.json"))["phase"])')
  if [[ "$phase" == off ]]; then break; fi
  if [[ "$phase" == install_failed ]]; then
    # Private diagnostics stay inside this disposable test VM, not public logs.
    python3 -c 'import json;print(json.load(open("/etc/quiet-scanner/protection/setup-stage.json")))'
    exit 1
  fi
  sleep 3
done
test "$phase" = off
! systemctl is-active --quiet quiet-scanner-protection.service
! systemctl is-active --quiet crowdsec.service
echo 'PASS: cancellation completed package setup without activating protection'
"$GUARD" '{"operation":"auto_enable"}' >/dev/null
for _ in $(seq 1 35); do
  "$GUARD" '{"operation":"status"}' >/tmp/quiet-setup-status.json
  if python3 -c 'import json;assert json.load(open("/tmp/quiet-setup-status.json"))["protecting"]'; then break; fi
  sleep 2
done
python3 -c 'import json;assert json.load(open("/tmp/quiet-setup-status.json"))["protecting"]'
test "$(stat -c %a /etc/quiet-scanner/protection/firewall.yaml)" = 600
test "$(stat -c %a /var/log/quiet-scanner-protection-setup.log)" = 600
! systemctl is-active --quiet crowdsec-firewall-bouncer.service
! systemctl is-enabled --quiet crowdsec-firewall-bouncer.service
python3 - <<'PY'
import json, yaml
r=json.load(open('/etc/quiet-scanner/protection/sources.json'))
assert r['managedEngine'] and r['inputs']
assert any(i['kind']=='syslog' for i in r['inputs']), r
c=yaml.safe_load(open('/etc/crowdsec/config.yaml.local'))
assert not c['api']['server']['online_client']['sharing']
assert not c['api']['server']['online_client']['pull']['community']
PY
echo 'PASS: one ON installed signed packages, detected log inputs and verified actual protection'
"$GUARD" '{"operation":"disable"}' >/dev/null
for _ in $(seq 1 20); do
  if ! systemctl is-active --quiet crowdsec.service; then break; fi
  sleep 1
done
! systemctl is-active --quiet crowdsec.service
"$GUARD" '{"operation":"auto_enable"}' >/dev/null
for _ in $(seq 1 35); do
  "$GUARD" '{"operation":"status"}' >/tmp/quiet-setup-status.json
  if python3 -c 'import json;assert json.load(open("/tmp/quiet-setup-status.json"))["protecting"]'; then break; fi
  sleep 2
done
python3 -c 'import json;assert json.load(open("/tmp/quiet-setup-status.json"))["protecting"]'
echo 'PASS: owned engine stops on OFF and subsequent ON reuses the setup'

#!/usr/bin/env bash
# Real systemd deployment tests. Disposable Ubuntu VM only.
set -euo pipefail
test "${QUIET_GUARD_DISPOSABLE_VM:-}" = YES
test "$(id -u)" = 0
binary=$(realpath "${1:?compiled binary}")
root=$(realpath "$(dirname "$0")/..")
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
umask 077
openssl genpkey -algorithm ED25519 -out "$temporary/private.pem"
openssl pkey -in "$temporary/private.pem" -pubout -out "$temporary/public.pem"
bash "$root/scripts/package.sh" "$binary" "$temporary/release1" 1 0.1.0 "$temporary/private.pem"
"$binary" bundle verify "$temporary/release1" "$temporary/public.pem" >/dev/null
python3 "$root/scripts/deploy.py" install --bundle "$temporary/release1" --trusted-key "$temporary/public.pem"
quiet-guard status > "$temporary/status.json"
python3 - "$temporary/status.json" <<'PY'
import json, sys
s=json.load(open(sys.argv[1]))
assert s['agent']=='running' and s['protection']=='not_configured' and s['risk']=='not_assessed'
PY
pid=$(systemctl show --property=MainPID --value quiet-guard.service)
test "$(awk '/^Uid:/ {print $2}' "/proc/$pid/status")" != 0
! ss -lntp | grep -F "pid=$pid," # Stage one opens no network listener.
echo 'PASS: independent service runs without root or a network listener; no false protection status'

# Tampering, replay and foreign config must all fail before service mutation.
printf '\nmodified\n' >> "$temporary/release1/quiet-guard.service"
if python3 "$root/scripts/deploy.py" install --bundle "$temporary/release1" --trusted-key "$temporary/public.pem"; then exit 1; fi
systemctl is-active --quiet quiet-guard.service
bash "$root/scripts/package.sh" "$binary" "$temporary/replay" 1 0.1.0 "$temporary/private.pem"
if python3 "$root/scripts/deploy.py" install --bundle "$temporary/replay" --trusted-key "$temporary/public.pem"; then exit 1; fi
systemctl is-active --quiet quiet-guard.service
bash "$root/scripts/package.sh" "$binary" "$temporary/release2" 2 0.1.1 "$temporary/private.pem"
python3 "$root/scripts/deploy.py" install --bundle "$temporary/release2" --trusted-key "$temporary/public.pem"
quiet-guard status >/dev/null
cp /etc/systemd/system/quiet-guard.service "$temporary/installed-unit"
printf '\n# user change\n' >> /etc/systemd/system/quiet-guard.service
if python3 "$root/scripts/deploy.py" uninstall; then exit 1; fi
grep -q '# user change' /etc/systemd/system/quiet-guard.service
cp "$temporary/installed-unit" /etc/systemd/system/quiet-guard.service
python3 "$root/scripts/deploy.py" uninstall
test ! -e /usr/local/lib/quiet-guard/quiet-guard
test ! -L /usr/local/bin/quiet-guard
test ! -e /etc/systemd/system/quiet-guard.service
echo 'PASS: tampered/replayed updates rejected, signed update accepted, user edits preserved, owned files removed'

# A correctly signed but non-starting unit must roll back a fresh installation.
bash "$root/scripts/package.sh" "$binary" "$temporary/failing" 3 0.1.2 "$temporary/private.pem"
sed -i 's|ExecStart=.*|ExecStart=/usr/bin/false|' "$temporary/failing/quiet-guard.service"
rm "$temporary/failing/manifest.json" "$temporary/failing/signature.bin"
"$binary" bundle manifest "$temporary/failing" release 3 0.1.2
openssl pkeyutl -sign -inkey "$temporary/private.pem" -rawin -in "$temporary/failing/manifest.json" -out "$temporary/failing/signature.bin"
if python3 "$root/scripts/deploy.py" install --bundle "$temporary/failing" --trusted-key "$temporary/public.pem"; then exit 1; fi
test ! -e /usr/local/lib/quiet-guard/quiet-guard
test ! -e /etc/systemd/system/quiet-guard.service
echo 'PASS: fresh install startup failure restores the pre-install state'

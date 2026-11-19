#!/usr/bin/env bash
# Root-only installation and authenticated HTTP operations in a disposable VM.
set -euo pipefail
test "${QUIET_GUARD_DISPOSABLE_VM:-}" = YES
test "$(id -u)" = 0
binary=$(realpath "${1:?compiled binary}")
root=$(realpath "$(dirname "$0")/..")
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
# Never dump environment, access links or credentials on failure.
trap 'echo "Dashboard test failed at line $LINENO"; systemctl status quiet-guard-dashboard.service quiet-guard-control.service --no-pager || true' ERR
umask 077
openssl genpkey -algorithm ED25519 -out "$temporary/private.pem"
openssl pkey -in "$temporary/private.pem" -pubout -out "$temporary/public.pem"
bash "$root/scripts/package.sh" "$binary" "$temporary/release" 1 0.1.0 "$temporary/private.pem"
python3 "$root/scripts/deploy.py" install --bundle "$temporary/release" --trusted-key "$temporary/public.pem"
mkdir -p /run/sshd
/usr/sbin/sshd -T > /dev/null
quiet-guard dashboard enable
python3 "$root/tests/test_dashboard_api.py"
# The UI must not survive foundational removal, and removal must not silently
# bypass its separate ownership record.
if python3 "$root/scripts/deploy.py" uninstall; then echo 'Removed an active dashboard foundation'; exit 1; fi
quiet-guard dashboard disable
systemctl is-active --quiet quiet-guard-exposure.timer
quiet-guard dashboard enable
quiet-guard dashboard rotate-token
python3 "$root/tests/test_dashboard_api.py" rotated
quiet-guard exposure disable
quiet-guard exposure remove
# Preserve operator edits instead of guessing how to restore them.
cp /etc/systemd/system/quiet-guard-dashboard.service "$temporary/web-unit"
printf '\n# operator edit\n' >> /etc/systemd/system/quiet-guard-dashboard.service
if quiet-guard dashboard remove; then echo 'Overwrote an operator unit'; exit 1; fi
cp "$temporary/web-unit" /etc/systemd/system/quiet-guard-dashboard.service
quiet-guard dashboard remove
systemctl is-active --quiet quiet-guard.service
test ! -e /etc/quiet-guard/dashboard/access-token
test ! -e /etc/systemd/system/quiet-guard-dashboard.service
python3 "$root/scripts/deploy.py" uninstall
echo 'PASS: authenticated loopback UI, restricted broker, real jobs, token rotation and owned teardown'

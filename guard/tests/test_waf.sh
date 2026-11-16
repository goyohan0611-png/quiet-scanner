#!/usr/bin/env bash
# Real Nginx -> pinned Lua forwarder -> actual CrowdSec/Coraza/CRS -> final response.
set -euo pipefail
test "${QUIET_GUARD_DISPOSABLE_VM:-}" = YES
test "$(id -u)" = 0
binary=$(realpath "${1:?compiled binary}")
root=$(realpath "$(dirname "$0")/..")
temporary=$(mktemp -d)
cleanup() {
  ip netns delete qg-waf-client 2>/dev/null || true
  ip link delete qg-waf-host 2>/dev/null || true
  if [[ -s "$temporary/app.pid" ]]; then kill "$(cat "$temporary/app.pid")" 2>/dev/null || true; fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'echo "WAF failure at line $LINENO"; python3 "$root/tests/waf_diagnostics.py"' ERR
umask 077
# Hosted runners preconfigure web document directories for the runner account.
# This disposable fixture uses root-owned package configuration parents, as R0
# requires; the product refuses writable/unowned parents rather than changing them.
for directory in /usr/share/nginx/modules-available /usr/share/nginx /usr/share /usr /etc/nginx /etc /; do
  chown root:root "$directory"
  chmod go-w "$directory"
done
openssl genpkey -algorithm ED25519 -out "$temporary/private.pem"
openssl pkey -in "$temporary/private.pem" -pubout -out "$temporary/public.pem"
bash "$root/scripts/package.sh" "$binary" "$temporary/release" 1 0.1.0 "$temporary/private.pem"
python3 "$root/scripts/deploy.py" install --bundle "$temporary/release" --trusted-key "$temporary/public.pem"
ip netns add qg-waf-client
ip link add qg-waf-host type veth peer name qg-waf-peer
ip link set qg-waf-peer netns qg-waf-client
ip addr add 10.204.0.1/24 dev qg-waf-host
ip link set qg-waf-host up
ip -n qg-waf-client addr add 10.204.0.2/24 dev qg-waf-peer
ip -n qg-waf-client link set lo up
ip -n qg-waf-client link set qg-waf-peer up
printf '\n10.204.0.1 guard.test api.guard.test\n' >> /etc/hosts
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/conf.d/quiet-guard-fixture.conf <<'CONF'
server {
 listen 18080;
 server_name guard.test;
 client_max_body_size 4m;
 location / { proxy_pass http://127.0.0.1:18081; }
 location /api/ { proxy_pass http://127.0.0.1:18081; }
 location = /login { proxy_pass http://127.0.0.1:18081; }
}
server {
 listen 18080;
 server_name api.guard.test;
 location / { proxy_pass http://127.0.0.1:18081; }
}
CONF
cp /etc/nginx/conf.d/quiet-guard-fixture.conf "$temporary/original.conf"
python3 - <<'PY' &
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):self.answer()
 def do_POST(self):self.answer()
 def answer(self):
  size=int(self.headers.get('Content-Length','0'));data=self.rfile.read(size)
  assert not self.headers.get('X-Quiet-Guard-Probe-Auth')
  assert not self.headers.get('X-Quiet-Guard-Diagnostic')
  self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b'{"ok":true}')
ThreadingHTTPServer(('127.0.0.1',18081),Handler).serve_forever()
PY
echo "$!" > "$temporary/app.pid"
nginx -t
systemctl restart nginx.service
request() { ip netns exec qg-waf-client curl --noproxy '*' --silent --show-error --max-time 5 -o /dev/null -w '%{http_code}' "$@"; }
test "$(request http://guard.test:18080/)" = 200
# A real reload command failure must restore configuration and stop our engine,
# even when the attempted rollback reload fails for the same external reason.
install -d -m 755 /etc/systemd/system/nginx.service.d
printf '[Service]\nExecReload=\nExecReload=/usr/bin/false\n' > /etc/systemd/system/nginx.service.d/quiet-guard-test.conf
systemctl daemon-reload
if quiet-guard waf enable --direct --probe-peer 10.204.0.2 --site http://guard.test:18080 --site http://api.guard.test:18080 --allow-insecure-probe; then exit 1; fi
cmp /etc/nginx/conf.d/quiet-guard-fixture.conf "$temporary/original.conf"
test ! -e /etc/nginx/conf.d/00-quiet-guard-waf.conf
! systemctl is-active --quiet quiet-guard-waf-engine
rm /etc/systemd/system/nginx.service.d/quiet-guard-test.conf
systemctl daemon-reload
quiet-guard waf enable
echo 'PASS: failed reload restores original bytes, stops the isolated engine, and supports retry'
systemctl is-active --quiet quiet-guard-waf-engine quiet-guard-waf-monitor
wait_phase() {
  local deadline=$((SECONDS+40))
  while ! python3 - "$1" <<'PY'
import json,sys
try:assert json.load(open('/var/lib/quiet-guard/waf/health.json'))['phase']==sys.argv[1]
except (OSError,AssertionError):sys.exit(1)
PY
  do
    if (( SECONDS>deadline )); then echo "Timed out waiting for WAF phase $1" >&2; return 1; fi
    sleep 1
  done
}
wait_phase awaiting_external_check
# Root-local probes use the wrong source and must never be accepted as evidence.
if python3 "$root/scripts/waf_probe.py" /etc/quiet-guard/waf/probe-client.json --once; then exit 1; fi
wait_phase awaiting_external_check
ip netns exec qg-waf-client python3 "$root/scripts/waf_probe.py" /etc/quiet-guard/waf/probe-client.json --once
wait_phase verified
echo 'PASS: external source GET/POST/body canary verified across two sites and every location; localhost cannot forge proofs'
test "$(request http://guard.test:18080/)" = 200
test "$(request http://guard.test:18080/login -H 'Content-Type: application/json' --data '{"email":"engineer@example.test","password":"QuietGuardSecretMarker"}')" = 200
test "$(request http://guard.test:18080/api/upload -F 'file=@/etc/hostname')" = 200
test "$(request http://guard.test:18080/api/update -H 'Content-Type: application/x-www-form-urlencoded' --data 'name=engineer&message=hello')" = 200
test "$(request 'http://guard.test:18080/.env')" = 403
test "$(request --get http://guard.test:18080/api/search --data-urlencode 'q=<script>alert(1)</script>')" = 403
test "$(request --get http://guard.test:18080/api/search --data-urlencode "q=1' OR 1=1--")" = 403
test "$(request http://guard.test:18080/api/update -H 'Content-Type: application/json' --data '{"password":"QuietGuardSecretMarker","q":"<script>alert(1)</script>"}')" = 403
# Client-supplied IP identity cannot replace the connection peer.
test "$(request http://guard.test:18080/.env -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Crowdsec-Appsec-Ip: 127.0.0.1')" = 403
sleep 11
python3 - <<'PY'
import json,pathlib
events=[json.loads(s) for s in pathlib.Path('/var/lib/quiet-guard/waf/events.jsonl').read_text().splitlines()]
assert events and all(e['peer']=='10.204.0.2' for e in events),events
assert all(set(e)=={'seq','epoch','boot_seconds','scope','peer','outcome'} for e in events)
assert all('QuietGuardSecretMarker' not in p.read_text(errors='replace') for p in pathlib.Path('/var/lib/quiet-guard/waf').glob('*.json*'))
import subprocess
assert 'QuietGuardSecretMarker' not in subprocess.run(['journalctl','-u','quiet-guard-waf-engine','--no-pager'],stdout=subprocess.PIPE).stdout.decode(errors='replace')
PY
cscli -c /etc/quiet-guard/waf/config.yaml alerts list -o json | python3 -c 'import json,sys;assert not json.load(sys.stdin)'
echo 'PASS: normal login/API/multipart pass; URI, query and JSON-body attacks blocked; metadata-only events and no diagnostic alerts'
# Oversized bodies stay available by default but are never counted as fully inspected.
# Use a supported content type: a CRS content-type-policy rejection is distinct
# from the body-size passthrough behavior this test is checking.
python3 -c 'import json;print(json.dumps({"message":"x"*1100000}),end="")' > "$temporary/large-body"
test "$(request http://guard.test:18080/api/upload --data-binary @"$temporary/large-body" -H 'Content-Type: application/json')" = 200
test "$(request http://guard.test:18080/api/upload --data-binary @"$temporary/large-body" -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/json')" = 200
wait_phase degraded
systemctl stop quiet-guard-waf-engine
test "$(request http://guard.test:18080/)" = 200
wait_phase unknown
systemctl start quiet-guard-waf-engine
wait_phase awaiting_external_check
ip netns exec qg-waf-client python3 "$root/scripts/waf_probe.py" /etc/quiet-guard/waf/probe-client.json --once
wait_phase degraded
echo 'PASS: incomplete bodies and fail-open are visible; engine restart invalidates old proofs'
# New Nginx locations invalidate evidence and are never overwritten on OFF.
cp /etc/nginx/conf.d/quiet-guard-fixture.conf "$temporary/active.conf"
printf '\n# operator change\n' >> /etc/nginx/conf.d/quiet-guard-fixture.conf
wait_phase unknown
if quiet-guard waf disable; then exit 1; fi
grep -q 'operator change' /etc/nginx/conf.d/quiet-guard-fixture.conf
cp "$temporary/active.conf" /etc/nginx/conf.d/quiet-guard-fixture.conf
quiet-guard waf disable
cmp /etc/nginx/conf.d/quiet-guard-fixture.conf "$temporary/original.conf"
test ! -e /etc/nginx/conf.d/00-quiet-guard-waf.conf
test "$(request http://guard.test:18080/.env)" = 200
quiet-guard waf enable
ip netns exec qg-waf-client python3 "$root/scripts/waf_probe.py" /etc/quiet-guard/waf/probe-client.json --once
quiet-guard waf remove
cmp /etc/nginx/conf.d/quiet-guard-fixture.conf "$temporary/original.conf"
test ! -e /etc/quiet-guard/waf
test ! -e /usr/local/lib/quiet-guard/waf
quiet-guard waf enable --direct --probe-peer 10.204.0.2 --site http://guard.test:18080 --site http://api.guard.test:18080 --allow-insecure-probe --failure-action deny --body-action deny
wait_phase awaiting_external_check
ip netns exec qg-waf-client python3 "$root/scripts/waf_probe.py" /etc/quiet-guard/waf/probe-client.json --once
wait_phase verified
test "$(request http://guard.test:18080/api/upload --data-binary @"$temporary/large-body" -H 'Content-Type: application/json')" = 413
systemctl stop quiet-guard-waf-engine
test "$(request http://guard.test:18080/)" = 503
wait_phase unknown
quiet-guard waf remove
python3 "$root/scripts/deploy.py" uninstall
echo 'PASS: edited Nginx configuration preserved; OFF restores exact original bytes; reenable and removal succeed'
echo 'PASS: explicit strict body policy returns 413; explicit strict engine-failure policy returns 503'

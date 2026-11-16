"""Apply the small, documented integration patches to the frozen source assets."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1] / 'vendor/waf'
assets = json.loads((root / 'assets.json').read_text())
meta = json.loads((root / 'upstream.json').read_text())
lua = assets['lua/crowdsec.lua']
lua = lua.replace('function csmod.AppSecCheck(ip)', 'function csmod.AppSecCheck(ip, skip_body)')
lua = lua.replace('local body, body_len, unreadable_body, close_body = get_body()', 'local body, body_len, unreadable_body, close_body = nil, 0, false, nil\n  if not skip_body then body, body_len, unreadable_body, close_body = get_body() end\n  if unreadable_body then return false, "ban", 503, {}, "Request body could not be inspected" end')
# Nginx adds raw request context to ngx.log lines. The controller records bounded,
# sanitized events instead of logging per-request transport errors or responses.
lua = lua.replace('ngx.log(ngx.ERR, "Fallback because of err: " .. err .. " (body: " .. body_len .. " bytes)")', '-- Transport failures are recorded by the Quiet Guard hook without raw request context.')
lua = lua.replace('ngx.log(ngx.DEBUG, "Appsec body response: " .. res.body)', '-- Do not log response details derived from requests.')
assets['lua/crowdsec.lua'] = lua
setup = assets['data/crs-setup.conf'].replace('log,auditlog,pass', 'nolog,noauditlog,pass')
assets['data/crs-setup.conf'] = setup
for name, reason in [('lua/crowdsec.lua', 'Unexpected/authentication responses and body read failures remain unverified; optionally inspect headers only for unsupported bodies; suppress per-request context logging.'), ('data/crs-setup.conf', 'Disable default request audit logging; Quiet Guard emits metadata-only events.')]:
    meta['files'][name]['patched_sha256'] = hashlib.sha256(assets[name].encode()).hexdigest()
    meta['files'][name]['patch'] = reason
(root / 'assets.json').write_text(json.dumps(assets, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
(root / 'upstream.json').write_text(json.dumps(meta, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

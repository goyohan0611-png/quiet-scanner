local q=quiet_guard_waf
local nonce=ngx.req.get_headers(128)['x-quiet-guard-probe-nonce']
if type(nonce)~='string' or #nonce~=32 or not nonce:match('^[a-f0-9]+$') then return end
local pending=q.dict:get('pending:'..nonce)
if not pending then return end
local proof=q.cjson.decode(pending)
if not proof or proof.peer~=ngx.var.remote_addr then return end
proof.status=ngx.status
q.dict:set('proof:'..proof.target..':'..proof.kind,q.cjson.encode(proof),180)
q.dict:delete('pending:'..nonce)

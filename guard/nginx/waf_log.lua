local q=quiet_guard_waf
local proof=ngx.ctx.quiet_guard_proof
if not proof or proof.peer~=ngx.var.remote_addr then return end
proof.status=ngx.status
q.dict:set('proof:'..proof.target..':'..proof.kind,q.cjson.encode(proof),180)

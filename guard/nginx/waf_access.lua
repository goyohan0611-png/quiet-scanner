local q = quiet_guard_waf
local scope = ngx.var.quiet_guard_scope_id or ''
if scope=='' or q.redirects[scope] or q.dict:get('enabled')==false then return end
local headers=ngx.req.get_headers(128)
local token=headers['x-quiet-guard-probe-auth']
local nonce=headers['x-quiet-guard-probe-nonce']
local kind=headers['x-quiet-guard-probe-kind']
local target=q.targets[scope..':'..ngx.var.host:lower()..':'..ngx.var.server_port]
local diag=token==q.cfg.probe_token and ngx.var.remote_addr==q.cfg.probe_peer and target
  and ngx.var.uri==target.path and (ngx.var.args==nil or ngx.var.args=='')
  and type(nonce)=='string' and #nonce==32 and nonce:match('^[a-f0-9]+$')
  and (kind=='get' or kind=='post' or kind=='block')
ngx.req.clear_header('X-Quiet-Guard-Probe-Auth')
ngx.req.clear_header('X-Quiet-Guard-Probe-Nonce')
ngx.req.clear_header('X-Quiet-Guard-Probe-Kind')
ngx.req.clear_header('X-Quiet-Guard-Diagnostic')
ngx.req.clear_header('X-Quiet-Guard-Action')
for _,name in ipairs({'Ip','Host','Verb','Uri','User-Agent','Api-Key','Transfer-Encoding'}) do
  ngx.req.clear_header('X-Crowdsec-Appsec-'..name)
end
local body_method=ngx.req.get_method()=='POST' or ngx.req.get_method()=='PUT' or ngx.req.get_method()=='PATCH' or ngx.req.get_method()=='DELETE'
local incomplete=body_method and ngx.req.http_version()>=2 and ngx.var.http_content_length==nil
local length=tonumber(ngx.var.http_content_length or '0')
if length and length>q.cfg.max_inspect_bytes then incomplete=true end
-- Chunked HTTP/1 bodies have no announced length. Nginx buffers them within
-- the site's existing limits; measure that buffer before choosing inspection.
if not incomplete and ngx.var.http_transfer_encoding then
  ngx.req.read_body()
  local data=ngx.req.get_body_data()
  if data then
    if #data>q.cfg.max_inspect_bytes then incomplete=true end
  else
    local filename=ngx.req.get_body_file()
    if filename then
      local file=io.open(filename,'rb')
      local size=file and file:seek('end')
      if file then file:close() end
      if not size or size>q.cfg.max_inspect_bytes then incomplete=true end
    end
  end
end
if ngx.var.http_content_encoding and ngx.var.http_content_encoding~='' and ngx.var.http_content_encoding~='identity' then incomplete=true end
local _,header_error=ngx.req.get_headers(128)
if header_error then incomplete=true end
if diag then ngx.req.set_header('X-Quiet-Guard-Diagnostic',q.cfg.probe_token) end
local outcome='inspected'
local inspection_failed=false
local ok, allowed, remediation, status, response, err
if incomplete and q.cfg.body_action=='deny' then
  allowed=false;status=413;outcome='policy_blocked'
else
  ok,allowed,remediation,status,response,err=pcall(q.cs.AppSecCheck,ngx.var.remote_addr,incomplete)
  if not ok or err then
    inspection_failed=true
    outcome=q.cfg.failure_action=='deny' and 'failed_closed' or 'failed_open'
    allowed=q.cfg.failure_action~='deny';status=503
  elseif not allowed then outcome='blocked'
  elseif incomplete then outcome='body_uninspected' end
end
ngx.req.clear_header('X-Quiet-Guard-Diagnostic')
ngx.req.clear_header('X-Quiet-Guard-Action')
local now=q.now()
if diag then
  if (kind=='get' and ngx.req.get_method()~='GET') or (kind~='get' and ngx.req.get_method()~='POST') then outcome='unverified' end
  ngx.ctx.quiet_guard_proof={target=target.id,scope=scope,kind=kind,peer=ngx.var.remote_addr,
    host=ngx.var.host:lower(),port=tonumber(ngx.var.server_port),generation=q.cfg.generation,nginx_epoch=q.epoch,
    engine_epoch=q.dict:get('engine_epoch') or '',boot_seconds=now,outcome=outcome}
  ngx.header['X-Quiet-Guard-Probe-Result']=outcome
  return ngx.exit(outcome=='blocked' and 403 or 204)
end
q.dict:incr(allowed and 'allowed' or 'blocked',1,0)
if incomplete then q.dict:incr('incomplete',1,0);q.dict:set('last_incomplete',now) end
if inspection_failed then q.dict:incr('failures',1,0);q.dict:set('last_failure',now) end
if outcome~='inspected' then
  local seq=q.dict:incr('event_seq',1,0)
  q.dict:set('event:'..tostring(seq%256),q.cjson.encode({seq=seq,epoch=q.epoch,boot_seconds=now,scope=scope,peer=ngx.var.remote_addr,outcome=outcome}))
end
if not allowed then return ngx.exit(status==413 and 413 or (inspection_failed and 503 or 403)) end

local q=quiet_guard_waf
if ngx.req.get_method()=='POST' then
  ngx.req.read_body()
  local raw=ngx.req.get_body_data()
  local body=raw and #raw<=256 and q.cjson.decode(raw)
  if not body then return ngx.exit(400) end
  if body.epoch and type(body.epoch)=='string' and #body.epoch<=64 and body.epoch:match('^[a-f0-9]+$') then q.dict:set('engine_epoch',body.epoch)
  elseif body.enabled==false then q.dict:set('enabled',false)
  else return ngx.exit(400) end
end
local result={schema=1,generation=q.cfg.generation,nginx_epoch=q.epoch,engine_epoch=q.dict:get('engine_epoch') or '',enabled=q.dict:get('enabled')~=false,
  allowed=q.dict:get('allowed') or 0,blocked=q.dict:get('blocked') or 0,incomplete=q.dict:get('incomplete') or 0,failures=q.dict:get('failures') or 0,
  last_incomplete=q.dict:get('last_incomplete') or 0,last_failure=q.dict:get('last_failure') or 0,event_seq=q.dict:get('event_seq') or 0,
  }
local proofs={};local events={}
for _, target in ipairs(q.cfg.targets) do for _,kind in ipairs({'get','post','block'}) do
  local item=q.dict:get('proof:'..target.id..':'..kind)
  if item then proofs[#proofs+1]=q.cjson.decode(item) end
end end
for index=0,255 do local item=q.dict:get('event:'..index);if item then events[#events+1]=q.cjson.decode(item) end end
-- Empty arrays must remain JSON arrays for the typed status reader.
ngx.header.content_type='application/json'
local encoded=q.cjson.encode(result)
ngx.print(encoded:sub(1,-2)..',"proofs":'..(#proofs>0 and q.cjson.encode(proofs) or '[]')..',"events":'..(#events>0 and q.cjson.encode(events) or '[]')..'}')

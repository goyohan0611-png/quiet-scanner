local cjson = require 'cjson.safe'
local ffi = require 'ffi'
pcall(ffi.cdef, 'struct qg_timespec { long tv_sec; long tv_nsec; }; int clock_gettime(int, void *);')
local file = assert(io.open('/etc/quiet-guard/waf/settings.json', 'rb'))
local cfg = assert(cjson.decode(file:read('*a'))); file:close()
local cs = require 'crowdsec'
local ok, err = cs.init('/etc/quiet-guard/waf/bouncer.conf', 'quiet-guard/0.1')
assert(ok, 'Quiet Guard inspection initialization failed')
local dict = ngx.shared.quiet_guard_waf
local runtime = {cfg=cfg,dict=dict,cjson=cjson,cs=cs,targets={},redirects={}}
function runtime.now()
  local ts = ffi.new('struct qg_timespec[1]')
  if ffi.C.clock_gettime(7, ts) ~= 0 then error('Quiet Guard boot clock unavailable') end
  return tonumber(ts[0].tv_sec)
end
runtime.epoch=tostring(runtime.now())..':'..tostring(ngx.worker.pid())..':'..tostring(ngx.now())
for _, target in ipairs(cfg.targets) do runtime.targets[target.scope..':'..target.host..':'..target.port]=target end
for _, scope in ipairs(cfg.scopes) do if scope.redirect_only then runtime.redirects[scope.id]=true end end
_G.quiet_guard_waf=runtime
dict:set('enabled',true)

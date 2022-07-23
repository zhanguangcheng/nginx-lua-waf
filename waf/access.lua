local init = require 'init'

local function waf_main()
    if init.white_ip_check() then
    elseif init.black_ip_check() then
    elseif init.user_agent_attack_check() then
    elseif init.cc_attack_check() then
    elseif init.cookie_attack_check() then
    elseif init.white_url_check() then
    elseif init.url_attack_check() then
    elseif init.url_args_attack_check() then
    elseif init.post_attack_check() then
    elseif ngx.var.http_Acunetix_Aspect then
        ngx.exit(444)
    elseif ngx.var.http_X_Scan_Memo then
        ngx.exit(444)
    else
        return
    end
end

-- 对于内部重定向或子请求，不进行限制。因为这些并不是真正对外的请求。
if not (ngx.req.is_internal()) then
    waf_main()
end

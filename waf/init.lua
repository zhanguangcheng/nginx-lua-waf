local config = require 'config'

local init = {}

-- Get WAF rule
function init.get_rule(rulefilename)
    local io = require 'io'
    local RULE_FILE = io.open(config.rule_dir .. '/' .. rulefilename, "r")
    if RULE_FILE == nil then
        return
    end
    local RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE, line)
    end
    RULE_FILE:close()
    return (RULE_TABLE)
end

-- ruls
local IP_WHITE_RULE = init.get_rule('whiteip.rule')
local IP_BLACK_RULE = init.get_rule('blackip.rule')
local URL_WHITE_RULES = init.get_rule('whiteurl.rule')
local COOKIE_RULES = init.get_rule('cookie.rule')
local URL_RULES = init.get_rule('url.rule')
local ARGS_RULES = init.get_rule('args.rule')
local USER_AGENT_RULES = init.get_rule('useragent.rule')
local POST_RULES = init.get_rule('post.rule')
local CC_COUNT = tonumber(string.match(config.cc_rate, '(.*)/'))
local CC_SECONDS = tonumber(string.match(config.cc_rate, '/(.*)'))
local DENY_HTML = init.get_rule(config.output_html)

-- args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

-- Get the client IP
function init.get_client_ip()
    local CLIENT_IP = "unknown"
    if config.get_client_ip_header ~= nil then
        CLIENT_IP = ngx.req.get_headers()[config.get_client_ip_header]
    end
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.var.remote_addr
    end
    return CLIENT_IP
end

-- Get the client user agent
function init.get_user_agent()
    local USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
        USER_AGENT = "unknown"
    end
    return USER_AGENT
end

-- WAF log record for json,(use logstash codec => json)
function init.log_record(method, url, data, ruletag)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_FILE = config.log_file
    local CLIENT_IP = init.get_client_ip()
    local USER_AGENT = init.get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {
        client_ip = CLIENT_IP,
        local_time = LOCAL_TIME,
        server_name = SERVER_NAME,
        user_agent = USER_AGENT,
        attackinitethod = method,
        req_url = url,
        req_data = data,
        rule_tag = ruletag
    }
    local LOG_LINE = cjson.encode(log_json_obj)
    local file = io.open(LOG_FILE, "a")
    if file == nil then
        return
    end
    file:write(LOG_LINE .. "\n")
    file:flush()
    file:close()
end

-- allow white ip
function init.white_ip_check()
    if config.white_ip_check == "on" then
        local WHITE_IP = init.get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _, rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP, rule, "isjo") then
                    init.log_record('White_IP', ngx.var_request_uri, WHITE_IP, rule)
                    return true
                end
            end
        end
    end
end

-- deny black ip
function init.black_ip_check()
    if config.black_ip_check == "on" then
        local BLACK_IP = init.get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _, rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP, rule, "isjo") then
                    init.log_record('BlackList_IP', ngx.var_request_uri, BLACK_IP, rule)
                    if config.waf_enable == "on" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

-- allow white url
function init.white_url_check()
    if config.white_url_check == "on" then
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _, rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI, rule, "isjo") then
                    return true
                end
            end
        end
    end
end

-- deny cc attack
function init.cc_attack_check()
    if config.cc_check == "on" then
        local CC_TOKEN = init.get_client_ip()
        if config.cc_token == 'uri' then
            CC_TOKEN = CC_TOKEN .. ngx.var.uri
        end
        local limit = ngx.shared.limit
        local req, _ = limit:get(CC_TOKEN)
        if req then
            if req > CC_COUNT then
                init.log_record('CC_Attack', ngx.var.request_uri, "-", "-")
                if config.waf_enable == "on" then
                    ngx.exit(403)
                end
            else
                limit:incr(CC_TOKEN, 1)
            end
        else
            limit:set(CC_TOKEN, 1, CC_SECONDS)
        end
    end
    return false
end

-- deny cookie
function init.cookie_attack_check()
    if config.cookie_check == "on" then
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _, rule in pairs(COOKIE_RULES) do
                if rule ~= "" and rulematch(USER_COOKIE, rule, "isjo") then
                    init.log_record('Deny_Cookie', ngx.var.request_uri, USER_COOKIE, rule)
                    if config.waf_enable == "on" then
                        init.waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- deny url
function init.url_attack_check()
    if config.url_check == "on" then
        local REQ_URI = ngx.var.request_uri
        for _, rule in pairs(URL_RULES) do
            if rule ~= "" and rulematch(REQ_URI, rule, "isjo") then
                init.log_record('Deny_URL', REQ_URI, REQ_URI, rule)
                if config.waf_enable == "on" then
                    init.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- deny url args
function init.url_args_attack_check()
    if config.url_args_check == "on" then
        for _, rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                local ARGS_DATA = nil
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~= "" and
                    rulematch(unescape(ARGS_DATA), rule, "isjo") then
                    init.log_record('Deny_URL_Args', ngx.var.request_uri, ARGS_DATA, rule)
                    if config.waf_enable == "on" then
                        init.waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- deny user agent
function init.user_agent_attack_check()
    if config.user_agent_check == "on" then
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _, rule in pairs(USER_AGENT_RULES) do
                if rule ~= "" and rulematch(USER_AGENT, rule, "isjo") then
                    init.log_record('Deny_USER_AGENT', ngx.var.request_uri, USER_AGENT, rule)
                    if config.waf_enable == "on" then
                        init.waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

-- 检查上传的文件后缀名
local function check_file_ext(ext)
    if not ext then
        return false
    end
    for _, v in pairs(config.white_upload_file_ext) do
        if ext == v then
            return false
        end
    end
    init.log_record('Deny_UPLOAD_FILE_EXT', ngx.var.request_uri, ext, "-")
    if config.waf_enable == "on" then
        init.waf_output()
        return true
    end
end

-- 检测post文本数据
local function check_body(data)
    if data ~= nil then
        for _, rule in pairs(POST_RULES) do
            if rule ~= "" and rulematch(unescape(data), rule, "isjo") then
                init.log_record("Deny_POST", ngx.var.request_uri, "-", rule)
                if config.waf_enable == "on" then
                    init.waf_output()
                    return true
                end
            end
        end
    end
    return false
end

-- 检测post表单数据
local function check_form_data()
    local sock, err = ngx.req.socket()
    if not sock then
        return false
    end
    ngx.req.init_body(128 * 1024)
    sock:settimeout(0)
    local content_length = nil
    content_length = tonumber(ngx.req.get_headers()['content-length'])
    local chunk_size = 4096
    if content_length < chunk_size then
        chunk_size = content_length
    end
    local size = 0
    while size < content_length do
        local data, err, partial = sock:receive(chunk_size)
        data = data or partial
        if not data then
            return false
        end
        ngx.req.append_body(data)
        size = size + string.len(data)
        local m = ngx.re.match(data, [[Content-Disposition: form-data;(.+)filename="(.+)\.(.*)"]], 'ijo')
        if m then
            if check_file_ext(m[3]) then
                return true
            end
            if check_body(data) then
                return true
            end
        else
            if rulematch(data, "Content-Disposition:(.+)", 'isjo') then
                if check_body(data) then
                    return true
                end
            end
        end
        local less = content_length - size
        if less < chunk_size then
            chunk_size = less
        end
    end
    ngx.req.finish_body()
    return false
end

-- deny post
function init.post_attack_check()
    if config.post_check == "on" and ngx.req.get_method() == "POST" then
        local header = ngx.req.get_headers()["content-type"]
        if header == nil then
            return false
        end
        if type(header) == "table" then
            header = header[1]
        end
        if string.find(header, "multipart/form%-data") then
            return check_form_data()
        end
        ngx.req.read_body()
        local BODY_DATA = ngx.req.get_body_data()
        if BODY_DATA == nil then
            return false
        end
        return check_body(BODY_DATA)
    end
    return false
end

-- WAF return
function init.waf_output()
    ngx.header.content_type = "text/html"
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say(DENY_HTML)
    ngx.exit(ngx.status)
end

return init

--WAF 配置文件 ,开启 = "on",关闭 = "off"
local config = {}

--waf的状态
config.waf_enable = "on"
--log保存目录，结尾不要写/
config.log_file = "/usr/local/openresty/nginx/logs/waf.log"
--waf规则保持路径
config.rule_dir = "/usr/local/openresty/nginx/conf/waf/rule-config"
--是否开启白名单url检测
config.white_url_check = "on"
--是否开启白名单ip检测
config.white_ip_check = "on"
--是否开启黑名单ip检测
config.black_ip_check = "on"
--是否开启url检测
config.url_check = "on"
--是否开启请求参数检测
config.url_args_check = "on"
--是否开启用户代理检测
config.user_agent_check = "on"
--是否开启Cookie检测
config.cookie_check = "on"
--是否开启CC检测
config.cc_check = "on"
--cc的请求数/每多少秒
config.cc_rate = "100/60"
-- 基于什么来检测cc，ip或uri，uri的话是用户ip+uri
config.cc_token = "ip"
-- 是否开启post检测
config.post_check = "on"
-- 允许上传的文件后缀名，开启post检测的时候才生效
config.white_upload_file_ext = {"jpg", "jpeg", "png", "gif", "webp", "pdf", "xlsx", "xls", "doc", "docx", "pptx", "ppt", "txt"}
-- 获取客户端ip的方式，默认留空则使用remote_addr，当有代理服务器时设置为X_real_ip,X_Forwarded_For来获取
config.get_client_ip_header = ""
-- nginx的Server响应头设置，留空去除
config.header_server = ""
-- php的x_powered_by响应头设置，留空去除
config.header_php = ""
-- 触发waf显示的html
config.output_html = 'deny.html'

return config
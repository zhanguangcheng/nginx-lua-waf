local config = require 'config'
ngx.header.server = config.header_server
ngx.header.x_powered_by = config.header_php

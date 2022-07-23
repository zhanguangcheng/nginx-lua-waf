# WAF 
使用Nginx+Lua实现自定义WAF（Web application firewall）

WAF一句话描述，就是解析HTTP请求（协议解析模块），规则检测（规则模块），做不同的防御动作（动作模块），并将防御过程（日志模块）记录下来。所以本文中的WAF的实现由五个模块(配置模块、协议解析模块、规则模块、动作模块、错误处理模块）组成。

来源：<https://github.com/unixhot/waf>

参考：
* https://github.com/openresty/lua-nginx-module
* https://github.com/wubonetcn/luawaf

## 功能列表：

1.	支持IP白名单和黑名单功能，直接将黑名单的IP访问拒绝。
2.	支持URL白名单，将不需要过滤的URL进行定义。
3.	支持User-Agent的过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
4.	支持CC攻击防护，单个URL指定时间的访问次数，超过设定值，直接返回403。
5.	支持Cookie过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
6.	支持URL过滤，匹配自定义规则中的条目，如果用户请求的URL包含这些，返回403。
7.	支持URL参数过滤，原理同上。
8.	支持日志记录，将所有拒绝的操作，记录到日志中去。
9.	日志记录为JSON格式，便于日志分析，例如使用ELK进行攻击日志收集、存储、搜索和展示。

在原来的基础上做的调整：
1. 将以前请求时读取规则配置修改为初始化时读取，以提高性能，更新规则后需要执行`nginx -s reload`
2. lua代码中的变量全部改为使用局部变量，通过return导出
3. 将lib.lua的代码合并到了init.lua
3. 新增cc配置基于ip还是uri，默认为IP
4. 默认删除nginx和php的版本响应头，防止泄漏软件和版本，配置项是:config.header_server,config.header_php
5. 修改获取IP默认获取remote_addr，防止伪造IP，如果有代理服务器再设置获取真实IP的请求头，配置项是:config.get_client_ip_header
6. 新增POST拦截支持，包含form-data、x-www-form-urlencoded、raw、binary的检测
7. 新增文件上传类型白名单限制，防止上传木马文件，配置项是:config.white_upload_file_ext
8. 不处理内部请求，防止重复执行waf，以提高性能
9. 所有匹配一律修改为不区分大小写的匹配
10. 新增扫描器拦截支持

## 文件说明
```
└─waf
  │ config.lua          # 配置文件
  │ init.lua            # nginx启动初始化时执行的脚本
  │ access.lua          # 每个请求到达时执行的脚本
  │ header_filter.lua   # 修改相应头的脚本
  └─rule-config         # 规则配置文件夹
      args.rule         # 请求参数规则
      blackip.rule      # 黑名单匹配规则
      cookie.rule       # cookie匹配规则
      deny.html         # 触发waf显示的html页面
      post.rule         # post匹配规则
      url.rule          # url匹配规则
      useragent.rule    # 用户代理匹配规则
      whiteip.rule      # 白名单IP列表
      whiteurl.rule     # 白名单url匹配规则
```

## 安装部署

以下方案选择其中之一即可：

- 选择1: 可以选择使用原生的Nginx，增加Lua模块实现部署。
- 选择2: 直接使用OpenResty（推荐）

### OpenResty安装

1 Yum安装OpenResty（推荐）

源码安装和Yum安装选择其一即可，默认均安装在/usr/local/openresty目录下。

```
wget https://openresty.org/package/centos/openresty.repo
sudo mv openresty.repo /etc/yum.repos.d/
sudo yum install -y openresty
```

2. 测试OpenResty和运行Lua

```
vim /usr/local/openresty/nginx/conf/nginx.conf
#在默认的server配置中增加
        location /hello {
            default_type text/html;
            content_by_lua_block {
                ngx.say("<p>hello, world</p>")
            }
        }
/usr/local/openresty/nginx/sbin/nginx -t
nginx: the configuration file /usr/local/openresty-1.17.8.2/nginx/conf/nginx.conf syntax is ok
nginx: configuration file /usr/local/openresty-1.17.8.2/nginx/conf/nginx.conf test is successful
/usr/local/openresty/nginx/sbin/nginx
```

3. 测试访问

```
curl http://127.0.0.1/hello
<p>hello, world</p>
```

### WAF部署

```bash
wget https://github.com/zhanguangcheng/nginx-lua-waf/archive/refs/heads/master.zip
unzip master.zip
cp -r ./nginx-lua-waf-master/waf /usr/local/openresty/nginx/conf/
```

vim /usr/local/openresty/nginx/conf/nginx.conf
#在http{}中增加，注意路径，同时WAF日志默认存放在/usr/local/openresty/nginx/logs/waf.log
```nginx
http {
    lua_shared_dict limit 50m;
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua;;";
    init_by_lua_file "/usr/local/openresty/nginx/conf/waf/init.lua";
    access_by_lua_file "/usr/local/openresty/nginx/conf/waf/access.lua";
    header_filter_by_lua_file "/usr/local/openresty/nginx/conf/waf/header_filter.lua";
}
```

```bash
ln -s /usr/local/openresty/lualib/resty/ /usr/local/openresty/nginx/conf/waf/resty
/usr/local/openresty/nginx/sbin/nginx -t
/usr/local/openresty/nginx/sbin/nginx -s reload
```

# 附录

## Nginx + Lua源码编译部署(不推荐)

1. Nginx安装必备的Nginx和PCRE软件包。

```
[root@nginx-lua ~]# cd /usr/local/src
[root@nginx-lua src]# wget http://nginx.org/download/nginx-1.12.1.tar.gz
[root@nginx-lua src]# wget https://nchc.dl.sourceforge.net/project/pcre/pcre/8.41/pcre-8.41.tar.gz
#其次，下载当前最新的luajit和ngx_devel_kit (NDK)，以及春哥（章）编写的lua-nginx-module
[root@nginx-lua src]# wget http://luajit.org/download/LuaJIT-2.0.5.tar.gz
[root@nginx-lua src]# wget https://github.com/simpl/ngx_devel_kit/archive/v0.3.0.tar.gz
[root@nginx-lua src]# wget wget https://github.com/chaoslawful/lua-nginx-module/archive/v0.10.10.zip
```

2. 最后，创建Nginx运行的普通用户

```
[root@nginx-lua src]# useradd -s /sbin/nologin -M www
```

3. 解压NDK和lua-nginx-module
```
[root@openstack-compute-node5 src]# tar zxvf v0.3.0.tar.gz
[root@openstack-compute-node5 src]# unzip -q v0.10.10.zip
```

4. 安装LuaJIT
Luajit是Lua即时编译器。
```
[root@webs-ebt src]# tar zxvf LuaJIT-2.0.5.tar.gz 
[root@webs-ebt src]# cd LuaJIT-2.0.5
[root@webs-ebt LuaJIT-2.0.5]# make && make install
```

5. 安装Nginx并加载模块
```
[root@webs-ebt src]# tar zxf nginx-1.12.1.tar.gz
[root@webs-ebt src]# tar zxvf pcre-8.41.tar.gz 
[root@webs-ebt src]# cd nginx-1.12.1
[root@webs-ebt nginx-1.12.1]# export LUAJIT_LIB=/usr/local/lib
[root@webs-ebt nginx-1.12.1]# export LUAJIT_INC=/usr/local/include/luajit-2.0
[root@webs-ebt nginx-1.12.1]#./configure --user=www --group=www --prefix=/usr/local/nginx-1.12.1/ --with-pcre=/usr/local/src/pcre-8.41 --with-http_stub_status_module --with-http_sub_module --with-http_gzip_static_module --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module  --add-module=../ngx_devel_kit-0.3.0/ --add-module=../lua-nginx-module-0.10.10/
[root@webs-ebt nginx-1.12.1]# make -j2 && make install
[root@webs-ebt nginx-1.12.1]# ln -s /usr/local/nginx-1.12.1 /usr/local/nginx
[root@webs-ebt nginx-1.12.1]# ln -s /usr/local/lib/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
```

> 如果不创建符号链接，可能出现以下异常：
```
error while loading shared libraries: libluajit-5.1.so.2: cannot open shared object file: No such file or directory
```

6. 测试安装

安装完毕后，下面可以测试安装了，修改nginx.conf 增加第一个配置。

```
        location /hello {
                default_type 'text/plain';
                content_by_lua 'ngx.say("hello,lua")';
        }
 
[root@webs-ebt src]# /usr/local/nginx/sbin/nginx -t
[root@webs-ebt src]# /usr/local/nginx/sbin/nginx -t
```

然后访问http://xxx.xxx.xxx.xxx/hello 如果出现hello,lua。表示安装完成,然后就可以。


### OpenResty源码编译部署（不推荐）

1. 安装依赖软件包

```
[root@opsany ~]# yum install -y readline-devel pcre-devel openssl-devel
```

2. 安装OpenResty


2.1 下载并编译安装OpenResty

```
[root@opsany ~]# cd /usr/local/src
[root@opsany src]# wget https://openresty.org/download/openresty-1.17.8.2.tar.gz
[root@opsany src]# tar zxf openresty-1.17.8.2.tar.gz
[root@opsany src]# cd openresty-1.17.8.2
[root@opsany openresty-1.17.8.2]# ./configure --prefix=/usr/local/openresty-1.17.8.2 \
--with-luajit --with-http_stub_status_module \
--with-pcre --with-pcre-jit \
--with-file-aio --with-threads
[root@opsany openresty-1.17.8.2]# gmake && gmake install
[root@opsany openresty-1.17.8.2]# cd
[root@opsany ~]# ln -s /usr/local/openresty-1.17.8.2/ /usr/local/openresty
```

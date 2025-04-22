# 定义Nginx版本变量
ARG NGINX_VERSION=1.26.3

# 第一阶段：构建阶段，使用alpine作为基础镜像
FROM alpine:3.19 AS base
LABEL maintainer="NGINX Docker Maintainers <justf>"

# 添加必要的软件源
RUN echo "http://dl-cdn.alpinelinux.org/alpine/v3.19/main" > /etc/apk/repositories && \
    echo "http://dl-cdn.alpinelinux.org/alpine/v3.19/community" >> /etc/apk/repositories && \
    apk update

# 安装基础构建工具和依赖
RUN apk add --no-cache \
    build-base \
    linux-headers \
    gcc \
    make \
    musl-dev \
    autoconf \
    libtool \
    automake \
    cmake \
    g++ \
    pcre-dev \
    zlib-dev \
    libxslt-dev \
    gd-dev \
    geoip-dev \
    readline-dev \
    libmaxminddb-dev \
    curl \
    git \
    patch \
    mercurial \
    gnupg

# 定义各种依赖组件的版本和下载地址
# Nginx相关补丁
ARG NGINX_VERSION
ARG NGINX_CRYPT_PATCH="https://raw.githubusercontent.com/kn007/patch/master/use_openssl_md5_sha1.patch"
ARG NGINX_SECURITY_PATCH="https://raw.githubusercontent.com/kn007/patch/master/nginx_security_headers.patch"

# OpenSSL配置
ARG OPENSSL_VERSION="1.1.1w"
ARG OPENSSL_URL="https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz"
ARG OPENSSL_PATCH="https://raw.githubusercontent.com/kn007/patch/master/openssl-1.1.1.patch"

# 使用Cloudflare优化的zlib
ARG ZLIB_URL="https://github.com/cloudflare/zlib.git"

# Jemalloc内存分配器
ARG JEMALLOC_VERSION=5.3.0
ARG JEMALLOC_URL="https://github.com/jemalloc/jemalloc/releases/download/${JEMALLOC_VERSION}/jemalloc-${JEMALLOC_VERSION}.tar.bz2"

# Brotli压缩
ARG BROTLI_URL="https://github.com/google/ngx_brotli.git"

# Headers More模块
ARG HEADERS_MORE_VERSION=0.35
ARG HEADERS_MORE_URL="https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz"

# GeoIP2模块
ARG GEOIP2_VERSION=3.4

# PCRE正则表达式库
ARG PCRE_VERSION="8.45"
ARG PCRE_URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre-${PCRE_VERSION}/pcre-${PCRE_VERSION}.tar.gz"
ARG PCRE_BACKUP_URL="https://ftp.exim.org/pub/pcre/pcre-${PCRE_VERSION}.tar.gz"

# 原子操作库
ARG LIBATOMIC_VERSION="7.8.2"
ARG LIBATOMIC_URL="https://github.com/ivmai/libatomic_ops/releases/download/v${LIBATOMIC_VERSION}/libatomic_ops-${LIBATOMIC_VERSION}.tar.gz"

# HTTP-FLV模块
ARG HTTP_FLV_URL="https://github.com/winshining/nginx-http-flv-module.git"

# FancyIndex模块
ARG FANCYINDEX_VERSION="0.5.2"
ARG FANCYINDEX_URL="https://github.com/aperezdc/ngx-fancyindex/releases/download/v${FANCYINDEX_VERSION}/ngx-fancyindex-${FANCYINDEX_VERSION}.tar.xz"

# 替换过滤器模块
ARG SUBS_FILTER_URL="https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git"

# LuaJIT配置
ARG LUAJIT_VERSION="2.1-20230119"
ARG LUAJIT_URL="https://github.com/openresty/luajit2/archive/refs/tags/v${LUAJIT_VERSION}.tar.gz"

# ngx_devel_kit
ARG NDK_VERSION="0.3.2"
ARG NDK_URL="https://github.com/vision5/ngx_devel_kit/archive/refs/tags/v${NDK_VERSION}.tar.gz"

# lua-nginx-module
ARG LUA_NGINX_VERSION="0.10.24"
ARG LUA_NGINX_URL="https://github.com/openresty/lua-nginx-module/archive/refs/tags/v${LUA_NGINX_VERSION}.tar.gz"

# 缓存清理模块
ARG CACHE_PURGE_VERSION="2.3"
ARG CACHE_PURGE_URL="https://github.com/nginx-modules/ngx_cache_purge/archive/refs/tags/${CACHE_PURGE_VERSION}.tar.gz"

# 设置工作目录
WORKDIR /usr/src/

# 克隆并编译Cloudflare优化的zlib
RUN \
  echo "Cloning zlib by cloudflare ..." \
  && cd /usr/src \
  && git clone --depth 1 ${ZLIB_URL} \
  && cd /usr/src/zlib \
  && make -f Makefile.in distclean \
  && ./configure \
  && make -j$(nproc)

# 下载并编译OpenSSL
RUN \
  echo "Downloading Openssl $OPENSSL_VERSION " \
  && cd /usr/src \
  && wget -O openssl-${OPENSSL_VERSION}.tar.gz ${OPENSSL_URL} \
  && tar -xzvf openssl-${OPENSSL_VERSION}.tar.gz \
  && cd /usr/src/openssl-${OPENSSL_VERSION} \
  && curl ${OPENSSL_PATCH} | patch -p1

# 下载并编译Nginx
RUN \
    echo "Cloning nginx $NGINX_VERSION ..." && \
    # 下载Nginx源码
    for i in $(seq 1 3); do \
        wget -O nginx.tar.gz https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && break || \
        echo "Download attempt $i failed, retrying..." && \
        sleep 5; \
    done && \
    # 解压源码
    tar -xzvf nginx.tar.gz -C /usr/src && \
    rm -f nginx.tar.gz && \
    cd /usr/src/nginx-${NGINX_VERSION} && \
    # 应用补丁，移除动态TLS记录补丁
    for patch_url in "${NGINX_CRYPT_PATCH}" "${NGINX_SECURITY_PATCH}"; do \
        echo "Applying patch: $patch_url" && \
        for i in $(seq 1 3); do \
            curl -f -L "$patch_url" | patch -p1 && break || \
            echo "Patch attempt $i failed, retrying..." && \
            sleep 5; \
        done; \
    done

# 克隆并编译GeoIP2模块
RUN \
  echo "Cloning ngx_http2_geoip2_module ..." \
  && cd /usr/src \
  && git clone --depth 1 --branch ${GEOIP2_VERSION} https://github.com/leev/ngx_http_geoip2_module 

# 克隆并编译Brotli模块
RUN \
  echo "Cloning ngx_brotli ..." \
  && cd /usr/src \
  && git clone ${BROTLI_URL} \
  && cd /usr/src/ngx_brotli \
  && git submodule update --init --recursive

# 克隆HTTP-FLV和替换过滤器模块
RUN \
  echo "Cloning nginx-http-flv-module & nginx_substitutions_filter ..." \
  && cd /usr/src \
  && git clone --depth 1 ${HTTP_FLV_URL} \
  && git clone --depth 1 ${SUBS_FILTER_URL} 

# 下载并编译LuaJIT
RUN \
  echo "Downloading and building LuaJIT ..." \
  && cd /usr/src \
  && wget -O luajit-${LUAJIT_VERSION}.tar.gz ${LUAJIT_URL} \
  && tar -xzvf luajit-${LUAJIT_VERSION}.tar.gz \
  && cd luajit2-${LUAJIT_VERSION} \
  && make -j$(nproc) \
  && make install \
  && ln -sf luajit-2.1.0-beta3 /usr/local/bin/luajit \
  && export LUAJIT_LIB=/usr/local/lib \
  && export LUAJIT_INC=/usr/local/include/luajit-2.1 \
  && ln -sf /usr/local/lib/libluajit-5.1.so.2 /usr/lib/libluajit-5.1.so.2

# 安装lua-resty-core
RUN \
  echo "Installing lua-resty-core ..." \
  && cd /usr/src \
  && git clone https://github.com/openresty/lua-resty-core.git \
  && cd lua-resty-core \
  && mkdir -p /usr/local/share/luajit-2.1.0-beta3/resty \
  && make install LUA_LIB_DIR=/usr/local/openresty/lualib \
  && ln -sf /usr/local/openresty/lualib/resty/core /usr/local/share/luajit-2.1.0-beta3/resty/core

# 安装lua-resty-lrucache
RUN \
  echo "Installing lua-resty-lrucache ..." \
  && cd /usr/src \
  && git clone https://github.com/openresty/lua-resty-lrucache.git \
  && cd lua-resty-lrucache \
  && mkdir -p /usr/local/share/luajit-2.1.0-beta3/resty \
  && make install LUA_LIB_DIR=/usr/local/openresty/lualib \
  && ln -sf /usr/local/openresty/lualib/resty/lrucache /usr/local/share/luajit-2.1.0-beta3/resty/lrucache

# 下载并编译ngx_devel_kit
RUN \
  echo "Downloading ngx_devel_kit ..." \
  && cd /usr/src \
  && wget -O ngx_devel_kit-${NDK_VERSION}.tar.gz ${NDK_URL} \
  && tar -xzvf ngx_devel_kit-${NDK_VERSION}.tar.gz

# 下载并编译lua-nginx-module
RUN \
  echo "Downloading lua-nginx-module ..." \
  && cd /usr/src \
  && wget -O lua-nginx-module-${LUA_NGINX_VERSION}.tar.gz ${LUA_NGINX_URL} \
  && tar -xzvf lua-nginx-module-${LUA_NGINX_VERSION}.tar.gz

# 下载并编译缓存清理模块
RUN \
  echo "Downloading ngx_cache_purge ..." \
  && cd /usr/src \
  && wget -O ngx_cache_purge-${CACHE_PURGE_VERSION}.tar.gz ${CACHE_PURGE_URL} \
  && tar -xzvf ngx_cache_purge-${CACHE_PURGE_VERSION}.tar.gz

# 下载并编译Headers More模块
RUN \
  echo "Downloading headers-more-nginx-module ..." \
  && cd /usr/src \
  && wget https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v${HEADERS_MORE_VERSION}.tar.gz -O headers-more-nginx-module.tar.gz \
  && tar -xf headers-more-nginx-module.tar.gz

# 下载并编译原子操作库
RUN \
  echo "Downloading libatomic_ops ..." \
  && cd /usr/src \
  && wget -O libatomic_ops-${LIBATOMIC_VERSION}.tar.gz ${LIBATOMIC_URL} \
  && tar -xzvf libatomic_ops-${LIBATOMIC_VERSION}.tar.gz \
  && cd /usr/src/libatomic_ops-${LIBATOMIC_VERSION} \
  &&  ./configure \
  && make -j $(nproc) \
  && ln -s .libs/libatomic_ops.a src/libatomic_ops.a

# 下载并编译FancyIndex模块
RUN \
  echo "Downloading ngx-fancyindex ..." \
  && cd /usr/src \
  && wget -O ngx-fancyindex-${FANCYINDEX_VERSION}.tar.xz ${FANCYINDEX_URL} \
  && tar -xvf ngx-fancyindex-${FANCYINDEX_VERSION}.tar.xz 

# 下载并编译PCRE
RUN \
  echo "Downloading PCRE ..." \
  && cd /usr/src \
  && for i in $(seq 1 3); do \
      echo "Download attempt $i..." && \
      (wget --no-check-certificate -O pcre-${PCRE_VERSION}.tar.gz ${PCRE_URL} || \
       wget --no-check-certificate -O pcre-${PCRE_VERSION}.tar.gz ${PCRE_BACKUP_URL} || \
       curl -k -L -o pcre-${PCRE_VERSION}.tar.gz ${PCRE_URL}) && break || \
      echo "Download attempt $i failed, retrying..." && \
      sleep 5; \
    done \
  && if [ -s pcre-${PCRE_VERSION}.tar.gz ]; then \
       tar -xzvf pcre-${PCRE_VERSION}.tar.gz; \
     else \
       echo "Failed to download PCRE" && exit 1; \
     fi

# 下载并编译Jemalloc
RUN \
    echo "Downloading and build jemalloc" && \
    cd /usr/src && \
    # 尝试多个下载源
    (wget -O jemalloc.tar.gz ${JEMALLOC_URL} || \
     wget -O jemalloc.tar.gz https://github.com/jemalloc/jemalloc/archive/refs/tags/${JEMALLOC_VERSION}.tar.gz) && \
    tar -xvf jemalloc.tar.gz && \
    cd jemalloc-${JEMALLOC_VERSION} && \
    ./configure && \
    make install -j$(nproc)

# 配置并编译Nginx
RUN \
	echo "Building nginx ..." \
	&& cd /usr/src/nginx-$NGINX_VERSION \
	&& export LUAJIT_LIB=/usr/local/lib \
	&& export LUAJIT_INC=/usr/local/include/luajit-2.1 \
	&& export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
	&& ./configure \
		--prefix=/etc/nginx \
		--sbin-path=/usr/sbin/nginx \
		--modules-path=/usr/lib/nginx/modules \
		--conf-path=/etc/nginx/nginx.conf \
		--error-log-path=/var/log/nginx/error.log \
		--http-log-path=/var/log/nginx/access.log \
		--pid-path=/var/run/nginx.pid \
		--lock-path=/var/run/nginx.lock \
		--http-client-body-temp-path=/var/cache/nginx/client_temp \
		--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
		--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
		--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
		--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
		--user=nginx \
		--group=nginx \
		--with-http_ssl_module \
		--with-http_realip_module \
		--with-http_addition_module \
		--with-http_sub_module \
		--with-http_dav_module \
		--with-http_flv_module \
		--with-http_mp4_module \
		--with-http_gunzip_module \
		--with-http_gzip_static_module \
		--with-http_random_index_module \
		--with-http_secure_link_module \
		--with-http_stub_status_module \
		--with-http_auth_request_module \
		--with-http_xslt_module \
		--with-http_image_filter_module=dynamic \
		--with-http_geoip_module=dynamic \
		--with-threads \
		--with-stream \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
		--with-stream_realip_module \
		--with-stream_geoip_module=dynamic \
		--with-http_slice_module \
		--with-mail \
		--with-mail_ssl_module \
		--with-compat \
		--with-file-aio \
		--with-http_v2_module \
		--with-http_v3_module \
		--with-http_degradation_module \
		--with-zlib=/usr/src/zlib \
		--with-pcre=/usr/src/pcre-${PCRE_VERSION} \
		--with-pcre-jit \
		--with-libatomic=/usr/src/libatomic_ops-${LIBATOMIC_VERSION} \
		--add-module=/usr/src/headers-more-nginx-module-${HEADERS_MORE_VERSION} \
		--add-module=/usr/src/ngx-fancyindex-${FANCYINDEX_VERSION} \
		--add-module=/usr/src/ngx_brotli \
		--add-module=/usr/src/ngx_http_geoip2_module \
		--add-module=/usr/src/nginx-http-flv-module \
		--add-module=/usr/src/ngx_http_substitutions_filter_module \
		--add-module=/usr/src/ngx_devel_kit-${NDK_VERSION} \
		--add-module=/usr/src/lua-nginx-module-${LUA_NGINX_VERSION} \
		--add-module=/usr/src/ngx_cache_purge-${CACHE_PURGE_VERSION} \
		--with-openssl=/usr/src/openssl-${OPENSSL_VERSION} \
		--with-openssl-opt="zlib enable-tls1_3 enable-weak-ssl-ciphers enable-ec_nistp_64_gcc_128 -ljemalloc -Wl,-flto" \
	&& make -j$(getconf _NPROCESSORS_ONLN)

# 安装Nginx并清理
RUN \
	cd /usr/src/nginx-$NGINX_VERSION \
	&& make install \
	&& rm -rf /etc/nginx/html/ \
	&& mkdir /etc/nginx/conf.d/ \
	&& strip /usr/sbin/nginx* \
	# 下载DH参数文件
	&& curl -fSL https://ssl-config.mozilla.org/ffdhe2048.txt > /etc/ssl/dhparam.pem \
	\
	# 安装gettext用于envsubst
	&& apk add --no-cache --virtual .gettext gettext \
	\
	# 收集运行时依赖
	&& scanelf --needed --nobanner /usr/sbin/nginx /usr/lib/nginx/modules/*.so /usr/bin/envsubst \
			| awk '{ gsub(/,/, "\nso:", $2); print "so:" $2 }' \
			| sort -u \
			| xargs -r apk info --installed \
			| sort -u > /tmp/runDeps.txt

# Verify modules directory content before exiting base stage
RUN echo "Listing modules directory content before exiting base stage:" && ls -l /usr/lib/nginx/modules/

# 第二阶段：最终镜像
FROM alpine:3.19
ARG NGINX_VERSION
ARG NGINX_COMMIT

ENV NGINX_VERSION=$NGINX_VERSION
ENV NGINX_COMMIT=$NGINX_COMMIT
ENV LUAJIT_LIB=/usr/local/lib
ENV LUAJIT_INC=/usr/local/include/luajit-2.1
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib

# 从构建阶段复制必要的文件
COPY --from=base /tmp/runDeps.txt /tmp/runDeps.txt
COPY --from=base /etc/nginx /etc/nginx
COPY --from=base /usr/lib/nginx/modules/*.so /usr/lib/nginx/modules/
COPY --from=base /usr/sbin/nginx /usr/sbin/
COPY --from=base /usr/local/lib/libluajit-5.1.so* /usr/local/lib/
COPY --from=base /usr/local/bin/luajit* /usr/local/bin/
COPY --from=base /usr/bin/envsubst /usr/local/bin/envsubst
COPY --from=base /etc/ssl/dhparam.pem /etc/ssl/dhparam.pem

# 复制配置文件
COPY nginx.conf /etc/nginx/nginx.conf
COPY cache_paths.conf /etc/nginx/conf.d/cache_paths.conf
COPY ssl_common.conf /etc/nginx/conf.d/ssl_common.conf
COPY security_headers.conf /etc/nginx/conf.d/security_headers.conf
COPY gzip.conf /etc/nginx/conf.d/gzip.conf
COPY proxy.conf /etc/nginx/conf.d/proxy.conf
COPY cache.conf /etc/nginx/conf.d/cache.conf
COPY rate_limit.conf /etc/nginx/conf.d/rate_limit.conf

# 设置Nginx用户和组，安装运行时依赖
# 安装基础工具和创建用户
RUN apk add --no-cache shadow && \
    groupadd -r nginx && \
    useradd -r -g nginx -s /sbin/nologin -d /var/cache/nginx nginx

# 安装基础依赖
RUN apk add --no-cache libgcc libc6-compat

# 安装动态模块所需的依赖
RUN apk add --no-cache \
    libxslt \
    libgd \
    geoip \
    libmaxminddb \
    libxml2 \
    libxml2-utils \
    libxslt-dev \
    gd-dev \
    geoip-dev \
    libmaxminddb-dev \
    tzdata

# 创建必要的目录
RUN mkdir -p /var/cache/nginx && \
    mkdir -p /var/cache/nginx/client_temp && \
    mkdir -p /var/cache/nginx/proxy_temp && \
    mkdir -p /var/cache/nginx/fastcgi_temp && \
    mkdir -p /var/cache/nginx/uwsgi_temp && \
    mkdir -p /var/cache/nginx/scgi_temp && \
    mkdir -p /var/log/nginx

# 设置日志文件
RUN touch /var/log/nginx/access.log /var/log/nginx/error.log && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

# 设置权限
RUN chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /etc/nginx

# 显示环境变量
RUN env | sort

# 测试Nginx配置
RUN nginx -V; nginx -t

# 暴露端口
EXPOSE 80 443

# 设置停止信号
STOPSIGNAL SIGTERM

# 启动命令
CMD ["nginx", "-g", "daemon off;"]

# 安装OpenResty
RUN \
  echo "Installing OpenResty ..." \
  && mkdir -p /usr/src \
  && cd /usr/src \
  && apk add --no-cache openresty git make

# 安装lua-resty-core
RUN \
  echo "Installing lua-resty-core ..." \
  && cd /usr/src \
  && git clone https://github.com/openresty/lua-resty-core.git \
  && cd lua-resty-core \
  && mkdir -p /usr/local/share/luajit-2.1.0-beta3/resty \
  && make install LUA_LIB_DIR=/usr/local/openresty/lualib \
  && ln -sf /usr/local/openresty/lualib/resty/core /usr/local/share/luajit-2.1.0-beta3/resty/core

# 安装lua-resty-lrucache
RUN \
  echo "Installing lua-resty-lrucache ..." \
  && cd /usr/src \
  && git clone https://github.com/openresty/lua-resty-lrucache.git \
  && cd lua-resty-lrucache \
  && mkdir -p /usr/local/share/luajit-2.1.0-beta3/resty \
  && make install LUA_LIB_DIR=/usr/local/openresty/lualib \
  && ln -sf /usr/local/openresty/lualib/resty/lrucache /usr/local/share/luajit-2.1.0-beta3/resty/lrucache
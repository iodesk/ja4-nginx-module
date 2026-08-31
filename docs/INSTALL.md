# Installasi Nginx + Module JA4 (Ubuntu/Debian)

---

## 1. Install Dependencies

```bash
sudo apt update

sudo apt install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    curl \
    wget \
    git \
    ca-certificates \
    libxml2-dev \
    libxslt1-dev \
    libgd-dev \
    libgeoip-dev \
    libgoogle-perftools-dev \
    libatomic1 \
    libperl-dev \
    libpam0g-dev \
    libgssapi-krb5-2 \
    libsasl2-2
```

---

## 2. Setup Build Directory

```bash
mkdir -p /opt/build && cd /opt/build
```

---

## 3. Build OpenSSL

```bash
wget https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz
tar xzf openssl-4.0.2.tar.gz
cd openssl-4.0.2

./config \
    --prefix=/opt/nginx-deps/openssl-4.0.2 \
    --openssldir=/opt/nginx-deps/openssl-4.0.2/ssl \
    enable-quic \
    no-tests \
    no-shared

make -j$(nproc)
make install_sw
```

---

## 4. Build PCRE2

```bash
wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.47/pcre2-10.47.tar.gz
tar xzf pcre2-10.47.tar.gz
cd pcre2-10.47/

./configure \
    --prefix=/opt/nginx-deps/pcre2-10.47 \
    --disable-shared \
    --enable-static \
    --disable-pcre2-16 \
    --disable-pcre2-32

make -j"$(nproc)"
sudo make install
```

---

## 5. Build Zlib

```bash
wget https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz
tar xzf zlib-1.3.2.tar.gz
cd zlib-1.3.2

./configure \
    --prefix=/opt/nginx-deps/zlib-1.3.2

make -j"$(nproc)"
sudo make install
```

---

## 6. Build Nginx

```bash
wget https://nginx.org/download/nginx-1.30.4.tar.gz
tar zxf nginx-1.30.4.tar.gz
cd nginx-1.30.4

make clean && \
rm -rf Makefile objs && \
./configure \
    --prefix=/usr/local/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --user=nginx \
    --group=nginx \
    --with-openssl=/opt/build/openssl-4.0.2 \
    --with-openssl-opt="enable-quic no-tests" \
    --with-pcre=/opt/build/pcre2-10.47 \
    --with-zlib=/opt/build/zlib-1.3.2 \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-http_realip_module \
    --with-http_stub_status_module \
    --with-http_auth_request_module \
    --with-threads \
    --with-file-aio \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-stream_realip_module \
    --with-http_gzip_static_module \
    --with-http_slice_module \
    --with-http_sub_module \
    --add-module=./ja4 \
    --add-module=./nginx-ssl-dynamic \
    --with-cc-opt="-g -O2 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -flto=auto -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -fPIC" \
    --with-ld-opt="-flto=auto -Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie" \
&& make -j"$(nproc)" \
&& make install && systemctl restart nginx
```

---

## 7. Setup Nginx User & Folders

```bash
sudo getent group nginx >/dev/null || sudo groupadd --system nginx

sudo id nginx >/dev/null 2>&1 || sudo useradd \
    --system \
    --gid nginx \
    --no-create-home \
    --home-dir /nonexistent \
    --shell /usr/sbin/nologin \
    nginx

sudo mkdir -p \
    /etc/nginx/conf.d \
    /etc/nginx/modules-enabled \
    /etc/nginx/sites-available \
    /etc/nginx/sites-enabled \
    /var/log/nginx

sudo chown -R nginx:nginx /var/log/nginx
```

---

## 8. Default SSL Certificate

```bash
sudo mkdir -p /etc/nginx/ssl/default

sudo openssl req -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -days 3650 \
    -keyout /etc/nginx/ssl/default/default.key \
    -out /etc/nginx/ssl/default/default.crt \
    -subj "/C=ID/ST=Central Java/L=Semarang/O=Default/CN=default"

sudo chown -R root:root /etc/nginx/ssl
sudo chmod 700 /etc/nginx/ssl/default
sudo chmod 600 /etc/nginx/ssl/default/default.key
sudo chmod 644 /etc/nginx/ssl/default/default.crt

sudo openssl dhparam \
    -out /etc/nginx/ssl/dhparams.pem \
    2048

sudo chown root:root /etc/nginx/ssl/dhparams.pem
sudo chmod 644 /etc/nginx/ssl/dhparams.pem
```

---

## 9. Systemd Service

Create the service file:

```bash
nano /etc/systemd/system/nginx.service
```

Paste the following content:

```ini
[Unit]
Description=The NGINX HTTP and reverse proxy server
Documentation=https://nginx.org/en/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid

ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/usr/sbin/nginx -s quit

TimeoutStopSec=5
KillSignal=SIGQUIT
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable nginx
sudo systemctl start nginx
```

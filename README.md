# 红果短剧 Web 版

> ⚠️ **免责声明**：本项目仅供个人学习与技术交流，所有内容数据来源于红果短剧公开接口，版权归原平台及内容方所有。请勿用于商业用途，如有侵权请联系删除。使用本项目产生的一切后果由使用者自行承担。

浏览器里刷红果短剧：FastAPI 后端 + 无依赖单页前端，手机 / 平板 / 电脑三端自适应。

## ✨ 功能

- **榜单浏览**：热播 / 推荐 / 新剧 / 最新上线 / 分类浏览（主题筛选）
- **搜索**：官网 SSR 搜索 + 每账号独立搜索历史 + 站内热搜聚合
- **优酷式播放页**：页内小窗、选集高亮定位、上下集、倍速、🎬 影院模式、自动连播
- **进度记忆**：断点续播、看过灰显、开播自动跳上次位置
- **扫码登录**（红果/抖音 APP 扫码）：观看记录与官方账号**双向云同步**（上报 + 拉取）
- **多访客隔离**：每浏览器独立 hg_sid，谁扫码同步谁的账号
- **可分享**：hash 路由 `#/d/剧ID`、`#/w/剧ID/集数`，链接直达那一集
- **收藏 / 历史**：本地 localStorage + 云端合并展示
- **秒开优化**：6 线程并行下载、看第 N 集后台预取第 N+1 集、多级缓存

## 🏗 架构

```
浏览器 UI ──► FastAPI (server.py) ──► fqnovel API（需签名）
                   │                        ▲
                   ├─ 官网 SSR 搜索（免签）   │ X-Argus/X-Gorgon
                   ├─ 离线解密串流 /stream   │
                   └─ 观看历史同步 reading.snssdk.com
```

- `server.py` — FastAPI 主服务（榜单/分类/剧集/解密串流/历史同步/热搜）
- `web/index.html` — 单文件前端（`/ui`，零构建零依赖）
- `hongguo.py` — fqnovel API 封装（签名调用、设备指纹池轮换）
- `frida/` — 离线解密与密钥处理（spade_a AES-CTR）
- `auth_login.py` — 扫码登录 + 观看历史同步
- 搜索走红果官网 SSR（`hongguoduanju.com/search/<kw>`，免签）
- 视频链路：fqnovel API（签名）取 video_model → 离线 AES-CTR 解密 → mp4 串流

## 🚀 部署

以 Ubuntu/Debian 为例，全程 root。

### 1. 系统依赖

```bash
apt update && apt install -y python3-venv ffmpeg openjdk-21-jre-headless nginx certbot python3-certbot-nginx
```

### 2. 拉代码 + Python 环境

```bash
git clone https://github.com/sgccdev/hongguo-web.git && cd hongguo-web
python3 -m venv venv
venv/bin/pip install fastapi "uvicorn[standard]" requests pycryptodome av pillow pillow-heif
mkdir -p stream-cache
```

### 3. 配置 .env

```bash
cat > .env << 'EOF'
HONGGUO_CONTENT_CONFIG=/绝对路径/hongguo-web/content-config.json
SIGN_SERVER=http://127.0.0.1:9099
HONGGUO_STREAM_CACHE=/绝对路径/hongguo-web/stream-cache
ADMIN_TOKEN=<openssl rand -hex 32 生成>
BIND_HOST=127.0.0.1
PORT=8077
EOF
```

| 变量 | 说明 |
|---|---|
| `HONGGUO_CONTENT_CONFIG` | 主 API 配置（仓库自带模板，复制改名即可） |
| `SIGN_SERVER` | 签名服务地址；可逗号分隔多个做轮询负载（如 `http://a:9099,http://b:9099`） |
| `HONGGUO_STREAM_CACHE` | 解密后视频缓存目录 |
| `ADMIN_TOKEN` | 管理接口密钥（/apikeys、/auth/token） |
| `BIND_HOST` | 生产建议 `127.0.0.1` 只走 nginx 反代 |

### 4. 签名服务（本仓库不含，需自备）

后端所有官方 API 调用都需要 X-Argus/X-Gorgon 签名。契约很简单——实现一个 HTTP 服务：

```
POST /sign
请求: {"url": "<完整请求URL>", "headers": {...}}
响应: {"X-Argus": "...", "X-Gorgon": "...", "X-Ladon": "...", ...}   # 签名后的请求头
```

可用 unidbg 加载官方 APK 里的安全库自建。跑起来后写 systemd 常驻：

```ini
# /etc/systemd/system/hongguo-sign.service
[Unit]
Description=Hongguo signer
After=network.target
[Service]
WorkingDirectory=/path/to/sign
ExecStart=/usr/bin/java --add-opens java.base/java.lang=ALL-UNNAMED -Xmx512m -cp unidbg-sign.jar <入口类> serve 9099
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
```

> 不配 `SIGN_SERVER` 也能跑：代码回落到进程内 Frida 签名（需 `pip install frida` + 真机/模拟器环境），仅适合 CLI 调试。

### 5. 主服务 systemd

```ini
# /etc/systemd/system/hongguo-web.service
[Unit]
Description=Hongguo Web (FastAPI)
After=network.target hongguo-sign.service
[Service]
WorkingDirectory=/绝对路径/hongguo-web
EnvironmentFile=/绝对路径/hongguo-web/.env
ExecStart=/绝对路径/hongguo-web/venv/bin/python server.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now hongguo-sign hongguo-web
curl http://127.0.0.1:8077/rank?board=hot   # 返回榜单 JSON 即成
```

### 6. nginx 反代 + HTTPS

```nginx
# /etc/nginx/sites-available/hongguo
server {
    listen 80;
    server_name your.domain.com;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / {
        proxy_pass http://127.0.0.1:8077;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;          # 视频直传
        proxy_read_timeout 300s;
    }
}
```

```bash
mkdir -p /var/www/acme
ln -s /etc/nginx/sites-available/hongguo /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
certbot certonly --webroot -w /var/www/acme -d your.domain.com   # 签发后给 80 配置加 443 server 块 + 301
```

打开 `https://your.domain.com/ui` 即可（根路径 `/` 自动 302 进 `/ui`）。

### 常见问题

- **剧集拉取失败**：九成是签名服务没起来，`curl -X POST http://127.0.0.1:9099/sign -H 'Content-Type: application/json' -d '{"url":"https://x","headers":{}}'` 自测
- **视频 502**：检查 ffmpeg 是否在 PATH、`HONGGUO_STREAM_CACHE` 目录可写
- **扫码登录失败**：确认 `x-tt-token` 有效（账号文件 `account_<sid>.json` 自动维护，删除即退出登录）
- **更新**：`git pull && systemctl restart hongguo-web`（前端改动无需重启）

## 📄 声明

仅供学习研究，不提供任何授权担保。内容版权归红果短剧及字节跳动所有，如有侵权请联系删除。

---

## 🐟 写在最后

这项目是我自己瞎搞着用的，全程一行代码没写（AI 代劳）。

起因很单纯：公司电脑不让随便装 APP，但我想上班摸鱼刷短剧。于是就有了这个东西——浏览器打开就能看，IT 部门问起来就是"在查资料"。

摸鱼虽好，可不要贪杯。被老板抓到别说是我教的。🐶

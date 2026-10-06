# -*- coding: utf-8 -*-
"""红果短剧 API 服务
部署在服务器,客户端连接后可搜索/看榜单/取剧集/拿视频直链。
签名由后端(Frida预言机/未来redroid/unidbg)提供,客户端无需签名。

启动: python server.py   (或 uvicorn server:app --host 0.0.0.0 --port 8000)

接口:
  GET /search?q=剧名
  GET /rank?board=recommend|hot|new&limit=30
  GET /filters?genre=comic_series         取某体裁全部筛选条件(实时)
  GET /browse?genre=ai_series&theme=玄幻&sort=hot_score&days=7   按筛选浏览(多选逗号分隔)
  GET /episodes?series_id=xxx
  GET /play?series_id=xxx&ep=1            取剧集信息(encrypted_url密文直链 + stream_url可播)
  GET /stream?series_id=xxx&ep=1          ★服务端【纯离线解密】后串流, 客户端拿到可播mp4
  GET /stream?vid=xxx&quality=1080p       也可直接按 vid + 清晰度; 支持 Range 拖动; <video>用?api_key=
"""
import re, os, io, time, threading, sys, secrets, shutil, logging, json, collections


class _KeyFilter(logging.Filter):
    """访问日志抹掉 api_key, 防凭据进 journal。
    注意: uvicorn AccessFormatter 会解包 record.args(5元组), 只能原地改路径段, 不能清空 args。"""
    def filter(self, record):
        try:
            if isinstance(record.args, tuple) and len(record.args) >= 3:
                a = list(record.args)
                if isinstance(a[2], str):
                    a[2] = re.sub(r"api_key=[^ &\"']+", "api_key=***", a[2])
                record.args = tuple(a)
            elif isinstance(record.msg, str):
                record.msg = re.sub(r"api_key=[^ &\"']+", "api_key=***", record.msg)
        except Exception:
            pass
        return True


logging.getLogger("uvicorn.access").addFilter(_KeyFilter())
from fastapi import FastAPI, HTTPException, Query, Depends, Request, Body
from fastapi.responses import StreamingResponse, JSONResponse, Response, FileResponse
import requests, urllib3
import hongguo as H
import auth_login as AUTH

# 离线解密(纯算法, 无app): spade_a → content key → AES-128-CTR 解密
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida"))
import offline_decrypt as OD
import offline_dl as ODL

STREAM_CACHE = os.environ.get("HONGGUO_STREAM_CACHE") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "downloads", ".stream_cache")
_dec_locks = {}; _dec_guard = threading.Lock()
def _dec_lock(key):
    with _dec_guard:
        return _dec_locks.setdefault(key, threading.Lock())

def _vm_track(vid, quality="best"):
    """取该集指定清晰度的 (main_url, spade_a, encrypt, definition, size)。"""
    vm = ODL._video_model(vid)
    if not vm:
        return None
    tracks = H.video_model_tracks(vm)
    tr, defn, _ = ODL._pick_track(tracks, quality)
    if not tr:
        return None
    enc = tr.get("encrypt_info") or {}
    meta = tr.get("video_meta") or {}
    return {"url": tr.get("main_url"), "spade_a": enc.get("spade_a"),
            "encrypt": bool(enc.get("encrypt")),
            "definition": meta.get("definition") or defn, "size": meta.get("size", 0)}

def _download_parallel(url, path, parts=6):
    """多线程 Range 分段下载 (CDN 支持 Range 时; 否则回落单流)。"""
    try:
        h = requests.head(url, timeout=15, allow_redirects=True)
        total = int(h.headers.get("content-length", 0))
        accept_range = "bytes" in (h.headers.get("accept-ranges") or "").lower()
    except Exception:
        total, accept_range = 0, False
    if not (total > 1 << 20 and accept_range):   # 小于1MB或不支持Range: 单流
        return H.download_file(url, path)
    sz = (total + parts - 1) // parts
    tmp_parts = [f"{path}.p{i}" for i in range(parts)]
    errs = []

    def _get(i):
        if i * sz >= total:
            return
        end = min((i + 1) * sz - 1, total - 1)
        try:
            r = requests.get(url, headers={"Range": f"bytes={i * sz}-{end}"},
                             stream=True, timeout=60)
            r.raise_for_status()
            with open(tmp_parts[i], "wb") as f:
                for chunk in r.iter_content(262144):
                    f.write(chunk)
        except Exception as e:
            errs.append(e)

    threads = [threading.Thread(target=_get, args=(i,), daemon=True) for i in range(parts)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    if errs:
        for p in tmp_parts:
            try: os.remove(p)
            except OSError: pass
        return H.download_file(url, path)   # 失败回落单流
    tmp = path + ".part"
    with open(tmp, "wb") as out:
        for p in tmp_parts:
            if os.path.exists(p):
                with open(p, "rb") as f:
                    shutil.copyfileobj(f, out, 1 << 20)
                os.remove(p)
    os.replace(tmp, path)


def _ensure_decrypted(vid, quality="best"):
    """下载 CDN 密文 + 纯离线解密, 返回缓存的明文 mp4 路径(已缓存则直接返回)。"""
    os.makedirs(STREAM_CACHE, exist_ok=True)
    safe_q = re.sub(r"[^\w]", "", str(quality)) or "best"
    out = os.path.join(STREAM_CACHE, f"{vid}_{safe_q}.mp4")
    if os.path.exists(out) and os.path.getsize(out) > 0:
        return out
    # offline_decrypt() falls back to a `.raw.mp4` path when ffmpeg is not
    # installed.  Treat that returned path as the cache artifact instead of
    # constructing a non-existent FileResponse target.
    raw = os.path.splitext(out)[0] + ".raw.mp4"
    if os.path.exists(raw) and os.path.getsize(raw) > 0:
        from desktop_remux import remux
        with _dec_lock(f"{vid}_{safe_q}"):
            return out if os.path.exists(out) else remux(raw, out)
    with _dec_lock(f"{vid}_{safe_q}"):                  # 同集并发请求只解一次
        if os.path.exists(out) and os.path.getsize(out) > 0:
            return out
        if os.path.exists(raw) and os.path.getsize(raw) > 0:
            from desktop_remux import remux
            return remux(raw, out)
        t = _vm_track(vid, quality)
        if not t or not t["url"]:
            raise HTTPException(404, "无直链/video_model")
        if not t["encrypt"]:
            _download_parallel(t["url"], out)
            return out
        ct = out + ".enc"
        _download_parallel(t["url"], ct)
        r = OD.offline_decrypt(t["spade_a"], ct, out)
        try:
            os.remove(ct)
        except OSError:
            pass
        if not (r and os.path.exists(r) and os.path.getsize(r) > 0):
            raise HTTPException(500, "解密失败(spade 异常或 ver2 视频?)")
        if os.path.abspath(r) != os.path.abspath(out):
            from desktop_remux import remux
            r = remux(r, out)
            if os.path.isfile(raw):
                os.remove(raw)
        return r

urllib3.disable_warnings()
app = FastAPI(title="红果短剧 API", version="1.0",
              docs_url=None, redoc_url=None, openapi_url=None)

# 图片转换(HEIC->JPEG, 浏览器不支持HEIC)
try:
    from PIL import Image
    import pillow_heif
    pillow_heif.register_heif_opener()
    _IMG_OK = True
except Exception:
    _IMG_OK = False
_img_cache = {}
_IMG_HOSTS = ("fqnovelpic.com", "byteimg.com", "qznovelvod.com", "douyinpic.com", "pstatp.com", "novelfmpic.com")

# ---- 鉴权(强制) + 限流 + 密钥管理 ----
# 数据接口强制要求有效密钥(来自 apikeys.json, 经 /admin 管理); 客户端不带有效密钥=401。
# ADMIN_TOKEN: 进入 /admin 管理页/接口的口令(与普通密钥分离)。
from apikeys import KeyStore
_keys = KeyStore()
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
if not ADMIN_TOKEN:
    import secrets as _sec
    ADMIN_TOKEN = _sec.token_hex(32)
    print("[server] 使用进程内临时管理口令；口令不输出、不持久化。")
RATE_PER_MIN = int(os.environ.get("RATE_PER_MIN", "120"))
_rl = {}
_rl_lock = threading.Lock()

# 免鉴权路径: 首页/网页/封面图/文档/管理页(管理页自己用 ADMIN_TOKEN 校验)
_EXEMPT = ("/", "/ui", "/img", "/docs", "/openapi.json", "/redoc", "/favicon.ico", "/auth/")
_ADMIN_PREFIX = "/admin"


def _check_admin(request: Request) -> bool:
    tok = request.headers.get("x-admin-token") or request.query_params.get("admin_token") or ""
    return bool(tok) and tok == ADMIN_TOKEN


# ============ 搜索历史(按 hg_sid 隔离) + 站内热搜聚合 ============
_HERE = os.path.dirname(os.path.abspath(__file__))
HOT_SEARCH_FILE = os.path.join(_HERE, "hot_search.json")
_SH_LOCK = threading.Lock()
_HOT_TTL = 7 * 86400  # 热搜统计 7 天滚动窗口


def _sh_path(sid):
    return os.path.join(_HERE, f"search_hist_{sid}.json")


def _load_json(p, default):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _atomic_write(p, obj):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, p)


@app.get("/search/history")
def get_search_history(request: Request):
    sid = _sid_cookie(request)
    if not sid:
        return {"history": []}
    with _SH_LOCK:
        his = _load_json(_sh_path(sid), [])
    return {"history": his[:10]}


@app.post("/search/history")
def post_search_history(request: Request, q: str = Body("", embed=True)):
    q = (q or "").strip()[:40]
    if not q:
        return {"ok": False}
    now = time.time()
    with _SH_LOCK:
        # 全站热搜聚合(所有用户, 7天窗口)
        hot = _load_json(HOT_SEARCH_FILE, [])
        hot.append({"q": q, "ts": now})
        hot = [h for h in hot if h.get("ts", 0) > now - _HOT_TTL][-3000:]
        _atomic_write(HOT_SEARCH_FILE, hot)
        # 个人历史(按账号隔离)
        sid = _sid_cookie(request)
        if sid:
            his = _load_json(_sh_path(sid), [])
            his = [q] + [x for x in his if x != q]
            _atomic_write(_sh_path(sid), his[:10])
    return {"ok": True}


@app.delete("/search/history")
def del_search_history(request: Request):
    sid = _sid_cookie(request)
    if sid:
        with _SH_LOCK:
            _atomic_write(_sh_path(sid), [])
    return {"ok": True}


_hot_cache = {"t": 0.0, "data": []}


@app.get("/search/hot")
def get_search_hot():
    if time.time() - _hot_cache["t"] < 300:
        return {"hot": _hot_cache["data"]}
    with _SH_LOCK:
        hot = _load_json(HOT_SEARCH_FILE, [])
    cutoff = time.time() - _HOT_TTL
    cnt = collections.Counter(h["q"] for h in hot if h.get("ts", 0) > cutoff)
    data = [q for q, _ in cnt.most_common(10)]
    _hot_cache["t"], _hot_cache["data"] = time.time(), data
    return {"hot": data}


@app.middleware("http")
async def auth_mw(request: Request, call_next):
    path = request.url.path
    if path == "/stats" or path.startswith(_ADMIN_PREFIX):
        # 管理/统计: 由各自处理器用 ADMIN_TOKEN 校验
        pass
    elif path not in _EXEMPT and not path.startswith("/auth/"):
        # 公开模式: 免密钥, 仅按 IP 限流防滥用
        key = "anon:" + (request.client.host if request.client else "?")
        now = time.time()
        with _rl_lock:
            desktop_segments = path.startswith("/desktop/hls/")
            limit = 600 if desktop_segments else RATE_PER_MIN
            bucket = _rl.setdefault((key, desktop_segments), [])
            while bucket and bucket[0] < now - 60:
                bucket.pop(0)
            if len(bucket) >= limit:
                return JSONResponse({"detail": f"超过限流 {limit}/分钟"}, status_code=429)
            bucket.append(now)
        _stats["requests"] += 1
    resp = await call_next(request)
    if resp.status_code >= 500:
        _stats["errors"] += 1
    return resp


def parse_range(ep, total):
    """'1' / '1-10' / 'all' -> 集号列表"""
    if not ep or ep == "all":
        return list(range(1, total + 1))
    m = re.match(r"(\d+)-(\d+)$", ep)
    if m:
        return list(range(int(m.group(1)), int(m.group(2)) + 1))
    if ep.isdigit():
        return [int(ep)]
    return []


_stats = {"start": time.time(), "requests": 0, "errors": 0, "risk": 0, "auth_fail": 0}


@app.get("/")
def index():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/ui", status_code=302)


@app.get("/stats")
def stats(request: Request):
    if not _check_admin(request):
        raise HTTPException(401, "需要 admin_token")
    import safeguards as SG
    up = int(time.time() - _stats["start"])
    # 签名后端健康
    backends = []
    for b in H.SIGN_SERVERS:
        try:
            rr = requests.get(b.rstrip("/") + "/", timeout=5).json()
            backends.append({"url": b, "ready": rr.get("ready"), "pid": rr.get("pid")})
        except Exception as e:
            backends.append({"url": b, "ready": False, "error": str(e)})
    return {"uptime_s": up, **{k: _stats[k] for k in ("requests", "errors", "risk", "auth_fail")},
            "cache_backend": "redis" if SG._redis else "memory",
            "sign_backends": backends,
            "download_tasks": len(H.manager().status())}


@app.get("/ui")
def ui():
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "index.html"))


# ---- 扫码登录(同步红果/抖音账号, 按 hg_sid cookie 隔离多访客) ----
def _sid_cookie(request: Request):
    sid = request.cookies.get("hg_sid") or ""
    return sid if re.fullmatch(r"[0-9a-f]{32}", sid) else None


@app.get("/auth/qrcode")
def auth_qrcode(request: Request):
    sid = _sid_cookie(request)
    new_sid = sid or secrets.token_hex(16)
    try:
        data = AUTH.new_qrcode(new_sid)
    except Exception as e:
        raise HTTPException(502, f"二维码获取失败: {e}")
    resp = JSONResponse(data)
    if not sid:
        resp.set_cookie("hg_sid", new_sid, max_age=365 * 86400, samesite="lax")
    return resp


@app.get("/auth/status")
def auth_status(token: str):
    if not token or len(token) > 128:
        raise HTTPException(400, "token 非法")
    try:
        return AUTH.check(token)
    except Exception as e:
        raise HTTPException(502, f"状态查询失败: {e}")


@app.get("/auth/me")
def auth_me(request: Request):
    a = AUTH.load_account(_sid_cookie(request))
    if not a:
        return {"logged_in": False}
    return {"logged_in": True, "user": a.get("user"), "saved_at": a.get("saved_at")}


@app.post("/auth/logout")
def auth_logout(request: Request):
    AUTH.logout(_sid_cookie(request))
    return {"ok": True}


# 历史列表缓存(60s) + 剧集元数据缓存(常驻,标题封面不变)
_hist_cache = {}   # key -> (ts, {"total":, "items": [...]})
_meta_cache = {}   # sid -> {"title","cover","ep_cnt"}
_HIST_TTL = 60


@app.post("/auth/sync_history")
def auth_sync_history(request: Request, payload: dict = Body(...)):
    """上报观看记录到官方账号"""
    sid = _sid_cookie(request)
    if not AUTH.load_account(sid):
        return {"ok": False, "msg": "未登录"}
    try:
        ok = AUTH.push_history(payload["series_id"],
                               int(payload.get("ep") or 0),
                               int(payload.get("position_ms") or 0), sid=sid)
        if ok:
            _hist_cache.pop(sid or "legacy", None)
        return {"ok": ok}
    except Exception as e:
        return {"ok": False, "msg": str(e)[:100]}


def _enrich_meta(sids):
    need = [s for s in sids if s and s not in _meta_cache]
    for i in range(0, len(need), 20):
        try:
            ms, _failed = H.get_episodes_batch(need[i:i + 20])
            for k, m in ms.items():
                get = (lambda k2: m.get(k2) or "") if isinstance(m, dict) \
                    else (lambda k2: getattr(m, {"cover": "cover_url"}.get(k2, k2), "") or "")
                _meta_cache[str(k)] = {"title": get("title"), "cover": get("cover"),
                                       "ep_cnt": (m.get("episode_cnt") if isinstance(m, dict)
                                                  else getattr(m, "episode_cnt", 0)) or 0}
        except Exception as e:
            print("[history] meta补全失败:", e)


@app.get("/auth/history")
def auth_history(request: Request):
    """拉取官方账号观看历史(60s缓存,标题封面服务端补全)"""
    sid = _sid_cookie(request)
    if not AUTH.load_account(sid):
        return {"logged_in": False, "items": []}
    key = sid or "legacy"
    now = time.time()
    ent = _hist_cache.get(key)
    if not ent or now - ent[0] > _HIST_TTL:
        try:
            d = AUTH.pull_history(sid=sid)
            items = [{"sid": str(it.get("book_id_str") or it.get("book_id") or ""),
                      "ep": it.get("vid_index", 0),
                      "pos_ms": it.get("current_play_position", 0),
                      "ts": it.get("read_timestamp_ms", 0)}
                     for it in (d.get("data_list") or [])
                     if not it.get("is_delete") and (it.get("book_id_str") or it.get("book_id"))]
            _enrich_meta([it["sid"] for it in items])
            ent = (now, {"total": d.get("total", 0), "items": items})
            _hist_cache[key] = ent
        except Exception as e:
            return {"logged_in": True, "items": [], "error": str(e)[:100]}
    data = ent[1]
    out = []
    for it in data["items"]:
        m = _meta_cache.get(it["sid"]) or {}
        out.append({**it, "title": m.get("title", ""), "cover": m.get("cover", "")})
    return {"logged_in": True, "total": data["total"], "items": out}


@app.get("/img")
def api_img(url: str):
    """图片代理。红果封面常返回 HEIC，浏览器不支持时转成 JPEG。"""
    from urllib.parse import urlparse
    try:
        raw = (url or "").strip()
        u = urlparse(raw)
        host = (u.hostname or "").lower()
        allowed = u.scheme in ("http", "https") and any(host == h or host.endswith("." + h) for h in _IMG_HOSTS)
        if not allowed:
            raise HTTPException(400, "图片域名不允许")
        cached = _img_cache.get(raw)
        if cached is not None:
            return Response(cached, media_type="image/jpeg", headers={"Cache-Control": "max-age=86400"})
        r = requests.get(raw, timeout=30, verify=True, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        content_type = (r.headers.get("content-type") or "").lower()
        data = r.content
        if _IMG_OK and ("heic" in content_type or u.path.lower().endswith(".heic")):
            img = Image.open(io.BytesIO(data))
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            out = io.BytesIO()
            img.save(out, format="JPEG", quality=88, optimize=True)
            data = out.getvalue()
            _img_cache[raw] = data
            return Response(data, media_type="image/jpeg", headers={"Cache-Control": "max-age=86400"})
        return Response(data, media_type=content_type or "image/jpeg", headers={"Cache-Control": "max-age=86400"})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(404, f"图片读取失败: {e}")


# ---------------- 密钥管理(需 ADMIN_TOKEN) ----------------
def _mask(k: str) -> str:
    return (k[:6] + "****" + k[-4:]) if len(k) > 12 else "****"


@app.get("/admin")
def admin_page():
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "admin.html"))


@app.get("/admin/keys")
def admin_list_keys(request: Request):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    return {"keys": _keys.list(), "enabled_count": _keys.count_enabled()}


@app.post("/admin/keys")
def admin_gen_key(request: Request, note: str = ""):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    key = _keys.generate(note)
    return {"ok": True, "key": key, "note": note}


@app.post("/admin/keys/revoke")
def admin_revoke_key(request: Request, key: str, enable: bool = False):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    return {"ok": _keys.revoke(key, enabled=enable)}


@app.delete("/admin/keys")
def admin_delete_key(request: Request, key: str):
    if not _check_admin(request):
        raise HTTPException(401, "admin_token 无效")
    return {"ok": _keys.delete(key)}


@app.get("/img")
def img(url: str):
    """封面图代理: 拉取并把HEIC转JPEG(浏览器不支持HEIC)。仅限字节图片域名。"""
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    if not any(host.endswith(h) for h in _IMG_HOSTS):
        raise HTTPException(400, "host not allowed")
    if url in _img_cache:
        return Response(_img_cache[url], media_type="image/jpeg",
                        headers={"Cache-Control": "max-age=86400"})
    try:
        raw = requests.get(url, timeout=20, verify=True).content
        if _IMG_OK:
            im = Image.open(io.BytesIO(raw)).convert("RGB")
            buf = io.BytesIO(); im.save(buf, "JPEG", quality=82); raw = buf.getvalue()
        if len(_img_cache) < 1000:
            _img_cache[url] = raw
        return Response(raw, media_type="image/jpeg", headers={"Cache-Control": "max-age=86400"})
    except Exception as e:
        raise HTTPException(404, str(e))


from search_pages import SearchPager
_search_pager = SearchPager(lambda params: H.api("GET", "/reading/bookapi/search/tab/v", extra_query=params, max_retries=1), H._parse_search_cell)


@app.get("/search/page")
def api_search_page(q: str = Query(..., min_length=1, max_length=80), cursor: str = Query(None, max_length=128)):
    """搜索: 抓红果官网 SSR 结果页(hongguoduanju.com/search/<kw>), 与桌面端搜索同源。"""
    try:
        r = requests.get("https://hongguoduanju.com/search/" + requests.utils.quote(q, safe=""),
                         headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
                         timeout=20)
        html = r.text
        items, seen = [], set()
        for m in re.finditer(r'<article class="pc-card-', html):
            seg = html[m.start():m.start() + 8000]
            sid_m = re.search(r'href="/detail\?series_id=(\d+)"', seg)
            if not sid_m:
                continue
            sid = sid_m.group(1)
            if sid in seen:
                continue
            seen.add(sid)
            img_m = re.search(r'<img class="pc-cover-[^"]*" src="([^"]+)"[^>]*alt="([^"]*)"', seg)
            hot_m = re.search(r'([\d.]+万?热度)', seg)
            intro_m = re.search(r'<p class="pc-intro-[^"]*">(.*?)</p>', seg, re.S)
            cats = re.findall(r'pc-category-text-[^"]*">([^<]+)<', seg)
            items.append({"series_id": sid,
                          "title": img_m.group(2) if img_m else "",
                          "score": hot_m.group(1) if hot_m else "",
                          "episode_cnt": len(re.findall(r'pc-episode-cell', seg)),
                          "play_cnt": 0,
                          "cover": img_m.group(1) if img_m else "",
                          "intro": re.sub(r"<[^>]+>", "", intro_m.group(1)).strip() if intro_m else "",
                          "categories": cats[:4]})
        return {"query": q, "items": items, "next_cursor": None}
    except Exception as e:
        raise HTTPException(502, f"搜索失败: {e}")


@app.get("/search")
def api_search(q: str = Query(..., description="剧名"),
              limit: int = Query(None, ge=1, le=40, description="结果上限(越小越快; 默认走 HG_SEARCH_MAX_ITEMS=20)")):
    try:
        return {"query": q, "results": H.search(q, max_items=limit)}
    except Exception as e:
        raise HTTPException(500, {"code": "SEARCH_FAILED", "error_type": type(e).__name__,
                                  "safe_response": getattr(e, "safe_response", None),
                                  "response": e.diagnostic if isinstance(e, H.UpstreamResponseError) else None,
                                  "signing_failed": "所有签名服务失败" in str(e),
                                  "certificate_failed": "CERTIFICATE_VERIFY_FAILED" in str(e),
                                  "invalid_json": "Expecting value" in str(e)})


@app.get("/rank")
def api_rank(board: str = "recommend", limit: int = 30):
    if board not in H.RANK_BOARDS:
        raise HTTPException(400, f"board必须是 {list(H.RANK_BOARDS)}")
    try:
        return {"board": board, "name": H.RANK_NAMES.get(board), "items": H.rank(board, limit)}
    except Exception as e:
        raise HTTPException(500, f"rank失败: {e}")


@app.get("/latest")
def api_latest(genre: str = "short_play", only_today: bool = True, limit: int = 120, refresh: bool = False, no_cache: bool = False):
    """最新上架/今日上新。genre: short_play(短剧)|comic_series(漫剧)|ai_series(AI短剧)。
    短剧支持精确'今日上新'(官方标签); 漫剧/AI官方无今日粒度,返回'7天内上新·最新上架'。"""
    if genre not in H.GENRES:
        raise HTTPException(400, f"genre必须是 {list(H.GENRES)}")
    try:
        items = H.latest(genre, only_today=only_today, max_items=limit, refresh=refresh or no_cache)
        # 诚实标注模式
        if genre == "short_play":
            mode = "今日上新" if only_today else "最新上架"
        else:
            mode = "7天内上新·最新上架"
        return {"genre": genre, "name": H.GENRE_NAMES.get(genre), "mode": mode,
                "only_today": only_today, "count": len(items), "items": items}
    except Exception as e:
        raise HTTPException(500, f"latest失败: {e}")


@app.get("/filters")
def api_filters(genre: str = "short_play"):
    """取某体裁的全部筛选条件(实时面板)。genre: short_play|comic_series|ai_series。
    返回各维度(type=select_items键) + 选项(id/name)。漫剧多一维 creation_status(状态)。"""
    if genre not in H.GENRES:
        raise HTTPException(400, f"genre必须是 {list(H.GENRES)}")
    try:
        return {"genre": genre, "name": H.GENRE_NAMES.get(genre), "rows": H.filters(genre)}
    except Exception as e:
        raise HTTPException(500, f"filters失败: {e}")


@app.get("/browse")
def api_browse(genre: str = "ai_series", theme: str = None, setting: str = None,
               background: str = None, sort: str = "online_time", gender: str = None,
               days: str = None, status: str = None, limit: int = 60):
    """按筛选条件浏览。各维度传中文名或id; 多选用逗号分隔(如 theme=玄幻,科幻)。可选项见 /filters。
    theme主题 setting设定 background背景 sort排序 gender受众 days时间(7/14/30/90) status状态(仅漫剧:已完结/连载中)。"""
    if genre not in H.GENRES:
        raise HTTPException(400, f"genre必须是 {list(H.GENRES)}")
    def _csv(v):
        return [x.strip() for x in v.split(",") if x.strip()] if v else None
    try:
        items = H.browse(genre, theme=_csv(theme), setting=_csv(setting), background=_csv(background),
                         sort=sort, gender=gender, days=days, status=status, max_items=limit)
        for it in items:                                  # 补服务端可播/取集链接(剧级→播第1集)
            sid = it["series_id"]
            vid = it.get("vid")
            # 有 vid(7.2.5.32 列表项自带)→ 直接 /stream?vid= 省服务端一次 get_episodes
            it["stream_url"] = f"/stream?vid={vid}" if vid else f"/stream?series_id={sid}&ep=1"
            it["episodes_url"] = f"/episodes?series_id={sid}"     # 列全集(拿各集再 /stream?...&ep=N)
        return {"genre": genre, "name": H.GENRE_NAMES.get(genre), "count": len(items),
                "note": "stream_url=播第1集; 其它集用 episodes_url 取集号后 /stream?series_id=&ep=N", "items": items}
    except Exception as e:
        raise HTTPException(500, f"browse失败: {e}")


@app.get("/episodes")
def api_episodes(series_id: str):
    try:
        meta, eps = H.get_episodes(series_id)
        return {"meta": meta, "episodes": eps}
    except Exception as e:
        raise HTTPException(500, f"episodes失败: {e}")


@app.post("/metrics/batch")
def api_metrics_batch(payload: dict = Body(...)):
    """批量补齐指标和封面。series_ids 每批最多20个拼接调用真实 multi_video_detail。"""
    raw_ids = payload.get("series_ids") or payload.get("series_id") or []
    if isinstance(raw_ids, str):
        series_ids = [x.strip() for x in raw_ids.split(",") if x.strip()]
    else:
        series_ids = [str(x).strip() for x in raw_ids if str(x).strip()]
    if not series_ids:
        raise HTTPException(400, "series_ids不能为空")
    if len(series_ids) > 200:
        raise HTTPException(400, "series_ids最多200个")
    batch_size = int(payload.get("batch_size") or 20)
    try:
        items, failed = H.get_episodes_batch(series_ids, batch_size=batch_size)
        rows = [items[sid] for sid in series_ids if sid in items]
        return {"count": len(rows), "items": rows, "failed": failed, "batch_size": max(1, min(batch_size, 20))}
    except Exception as e:
        raise HTTPException(500, f"metrics batch失败: {e}")


@app.get("/play")
def api_play(series_id: str, ep: str = "all"):
    """返回剧集的真实视频直链(客户端可直接下载/播放,无需签名)"""
    stage = "episodes"
    try:
        meta, eps = H.get_episodes(series_id)
        want = set(parse_range(ep, len(eps)))
        sel = [e for e in eps if (e["index"] or 0) in want]
        stage = "video_model"
        urls = H.get_video_urls([e["vid"] for e in sel])
        out = []
        for e in sel:
            info = urls.get(e["vid"], {})
            out.append({"index": e["index"], "vid": e["vid"], "title": e["title"],
                        "duration": e["duration"],
                        # url 是 CDN 密文直链(CENC加密, 直接播放是花屏); 要可播用 stream_url(服务端已解密)
                        "encrypted_url": info.get("url"), "backup": info.get("backup"),
                        "size": info.get("size"), "definition": info.get("definition"),
                        "shape": info.get("shape"), "url_is_http": info.get("url_is_http"),
                        "stream_url": f"/stream?vid={e['vid']}"})
        return {"series_id": series_id, "title": meta["title"],
                "note": "encrypted_url 为CENC密文直链; 可播放用 stream_url(服务端纯离线解密)", "episodes": out}
    except Exception as e:
        import traceback
        frames = [{"file": os.path.basename(f.filename), "line": f.lineno, "function": f.name}
                  for f in traceback.extract_tb(e.__traceback__)]
        raise HTTPException(500, {"code": "PLAY_FAILED", "stage": stage, "frames": frames,
                                  "model_shape": getattr(e, "model_shape", None),
                                  "error_type": type(e).__name__,
                                  "response": e.diagnostic if isinstance(e, H.UpstreamResponseError) else None})


@app.get("/download")
def api_download(series_id: str, ep: str = "all", ep_covers: bool = False):
    """提交下载任务到服务器本地(并发+断点续传)。返回 task_id, 用 /download/status 查进度。"""
    try:
        tid = H.manager().submit(series_id, ep, ep_covers)
        return {"task_id": tid, "status_url": f"/download/status?task_id={tid}"}
    except Exception as e:
        raise HTTPException(500, f"download失败: {e}")


@app.get("/download/status")
def api_download_status(task_id: str = None):
    return H.manager().status(task_id)


@app.get("/video_url")
def api_video_url(vid: str):
    """按单个 vid 取真实视频直链(供外部源模块调用)。"""
    try:
        urls = H.get_video_urls([vid])
        info = urls.get(str(vid)) or {}
        if not info.get("url"):
            raise HTTPException(404, "无直链")
        return {"vid": vid, "url": info.get("url"), "backup": info.get("backup"),
                "size": info.get("size"), "definition": info.get("definition")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"video_url失败: {e}")


_warm_lock = threading.Lock()
_warm_recent = {}   # (series_id, ep) -> ts, 5分钟内不重复预热


def _warm_async(series_id, ep):
    """后台预取某集: 下载+解密进缓存, 之后 /stream 秒回。"""
    key = (str(series_id), int(ep))
    now = time.time()
    with _warm_lock:
        if now - _warm_recent.get(key, 0) < 300:
            return
        _warm_recent[key] = now
        for k in [k for k, v in _warm_recent.items() if now - v > 600]:
            _warm_recent.pop(k, None)

    def _run():
        try:
            meta, eps = H.get_episodes(str(series_id))
            target = next((e for e in eps if (e["index"] or 0) == int(ep)), None)
            if target:
                t0 = time.time()
                _ensure_decrypted(str(target["vid"]))
                print(f"[warm] {meta['title']} 第{ep}集 预热完成 {time.time()-t0:.1f}s")
        except Exception as e:
            print(f"[warm] {series_id} ep{ep} 失败: {e}")
    threading.Thread(target=_run, daemon=True).start()


@app.get("/warm")
def api_warm(series_id: str, ep: str = "1"):
    """详情页打开即预热 (前端 fire-and-forget)。"""
    if re.fullmatch(r"[0-9]{8,24}", str(series_id)) and str(ep).isdigit():
        _warm_async(series_id, int(ep))
    return {"ok": True}


@app.get("/stream")
def api_stream(series_id: str = None, ep: str = "1", vid: str = None, quality: str = "best"):
    """服务器代理串流单集 —— 已做【纯离线解密】, 客户端拿到的是可播 mp4(非密文)。
    用法: /stream?series_id=xxx&ep=1  或  /stream?vid=xxx  [&quality=1080p&api_key=...]
    首次会下载+解密并缓存(downloads/.stream_cache), 之后秒回; FileResponse 支持 Range 拖动。
    注: <video> 标签无法带请求头, 用 ?api_key= 传密钥。"""
    try:
        fname = None
        if not vid:
            if not series_id:
                raise HTTPException(400, "需 series_id+ep 或 vid")
            meta, eps = H.get_episodes(series_id)
            idx = int(ep) if str(ep).isdigit() else 1
            target = next((e for e in eps if (e["index"] or 0) == idx), None)
            if not target:
                raise HTTPException(404, "集号不存在")
            vid = target["vid"]
            fname = f"{H.sanitize(meta['title'])}_第{idx:03d}集.mp4"
            if idx < len(eps):
                _warm_async(series_id, idx + 1)   # 看N集时后台预取N+1
        path = _ensure_decrypted(vid, quality)   # 下载密文+离线解密+缓存
        if os.environ.get("HONGGUO_SESSION_API_KEY"):
            from desktop_encode import encode_h264
            with _dec_lock(f"desktop-h264-v1:{vid}:{quality}"):
                path = encode_h264(path)
        fname = fname or f"{vid}.mp4"
        from urllib.parse import quote as _q
        cd = f"inline; filename=\"{vid}.mp4\"; filename*=UTF-8''{_q(fname)}"
        # FileResponse 自动处理 HTTP Range(206), 支持播放器 seek
        return FileResponse(path, media_type="video/mp4", headers={"Content-Disposition": cd})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"stream失败: {e}")


if os.environ.get("HONGGUO_SESSION_API_KEY") and os.environ.get("HONGGUO_HLS_WORK_DIR"):
    from desktop_hls_service import HlsJobs, make_router, DESKTOP_ORIGINS
    from fastapi.middleware.cors import CORSMiddleware

    def _desktop_source(series_id, episode):
        _, episodes = H.get_episodes(series_id)
        target = next((item for item in episodes if item.get("index") == episode), None)
        if not target or not re.fullmatch(r"[0-9]{8,24}", str(target.get("vid", ""))):
            raise ValueError("Episode media identity unavailable")
        return _ensure_decrypted(str(target["vid"]), "desktop-resolution-v1")

    _desktop_jobs = HlsJobs(os.environ["HONGGUO_HLS_WORK_DIR"], _desktop_source)
    app.include_router(make_router(_desktop_jobs, _keys.is_valid))
    # Must wrap authentication so browser preflight can complete, but every
    # actual HLS request still requires the process-only key and reviewed origin.
    app.add_middleware(CORSMiddleware, allow_origins=DESKTOP_ORIGINS,
                       allow_methods=["GET", "HEAD", "POST", "DELETE"],
                       allow_headers=["x-api-key", "range"],
                       expose_headers=["content-range", "accept-ranges"])


if __name__ == "__main__":
    import uvicorn
    # 默认只绑本机(脱机直连由同机 xinge 走 127.0.0.1 调); 需对外可设 BIND_HOST=0.0.0.0
    uvicorn.run(app, host=os.environ.get("BIND_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))

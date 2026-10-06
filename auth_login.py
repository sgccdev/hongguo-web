# -*- coding: utf-8 -*-
"""扫码登录: fanqienovel passport (aid=2503), 红果/番茄/抖音同账号体系。
流程: get_qrcode 拿 token+二维码 -> check_qrconnect 轮询 -> confirmed 后收割 session cookies。
登录态按访客隔离: 每个浏览器一个 hg_sid cookie -> account_<sid>.json。
(旧全局 account.json 仅留作备份, 不再自动回落——否则新设备会顶旧号)"""
import os, json, time, threading, re
import requests

BASE = os.path.dirname(os.path.abspath(__file__))
LEGACY_PATH = os.path.join(BASE, "account.json")  # 备份, 不再使用
PASSPORT = "https://fanqienovel.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

_sessions = {}   # token -> {"sess": Session, "ts": float, "sid": str}
_lock = threading.Lock()


def _path(sid=None):
    if sid and re.fullmatch(r"[0-9a-f]{32}", sid):
        return os.path.join(BASE, f"account_{sid}.json")
    return None


def _params(extra=None):
    p = {"aid": "2503", "language": "zh", "account_sdk_source": "web",
         "passport_jssdk_version": "3.0.16", "passport_jssdk_type": "normal"}
    if extra:
        p.update(extra)
    return p


def _forge_qrcode(qr_b64):
    """把官方 QR 内容里的 aid 改成红果(8662), 让红果APP可扫。失败则返回原码。
    实测红果APP扫码器不接 scan-auth 流程(只当网页打开), 默认关闭, 设 HONGGUO_FORGE_AID=1 开启。"""
    if not os.environ.get("HONGGUO_FORGE_AID"):
        return qr_b64
    try:
        import base64, io, urllib.parse as up
        import qrcode as _qr
        from pyzbar.pyzbar import decode as _decode
        from PIL import Image as _Img
        img = _Img.open(io.BytesIO(base64.b64decode(qr_b64)))
        orig = _decode(img)[0].data.decode()
        u = up.urlparse(orig)
        q = dict(up.parse_qsl(u.query))
        if "qr_source_aid" not in q:
            return qr_b64
        q["qr_source_aid"] = "8662"
        q["outSideAppName"] = "红果短剧"
        forged = up.urlunparse((u.scheme, u.netloc, u.path, u.params,
                                up.urlencode(q), u.fragment))
        buf = io.BytesIO()
        _qr.make(forged, box_size=8, border=2).save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        print("[auth] 伪造QR失败,用原码:", e)
        return qr_b64


def new_qrcode(sid=None):
    s = requests.Session()
    s.headers.update({"User-Agent": UA,
                      "Referer": PASSPORT + "/main/writer/login"})
    r = s.get(PASSPORT + "/passport/web/get_qrcode/",
              params=_params({"next": PASSPORT + "/main/writer/login",
                              "need_logo": "true"}), timeout=20)
    j = r.json()
    d = j.get("data") or {}
    token = d.get("token")
    if not token or d.get("error_code"):
        raise RuntimeError("get_qrcode失败: error_code=%s" % d.get("error_code"))
    now = time.time()
    with _lock:
        for k in [k for k, v in _sessions.items() if now - v["ts"] > 600]:
            _sessions.pop(k, None)
        _sessions[token] = {"sess": s, "ts": now, "sid": sid}
    return {"token": token, "qrcode": _forge_qrcode(d.get("qrcode", "")),
            "expire_time": d.get("expire_time", 0)}


def check(token):
    with _lock:
        ent = _sessions.get(token)
    if not ent:
        return {"status": "expired"}
    s = ent["sess"]
    r = s.get(PASSPORT + "/passport/web/check_qrconnect/",
              params=_params({"next": "/", "token": token}), timeout=20)
    j = r.json()
    d = j.get("data") or {}
    if d.get("error_code"):
        return {"status": "expired", "error_code": d.get("error_code")}
    status = d.get("status") or "new"
    if status != "new":
        print(f"[auth] token={token[:8]}.. 状态={status} ec={d.get('error_code')}")
    if status in ("confirmed", "complete", "success") or d.get("redirect_url"):
        redir = d.get("redirect_url")
        if redir:
            try:
                s.get(redir, timeout=20, allow_redirects=True)
            except Exception:
                pass
        cookies = s.cookies.get_dict()
        user = fetch_user(s)
        sid = ent.get("sid")
        _save(cookies, user, sid)
        with _lock:
            _sessions.pop(token, None)
        return {"status": "confirmed", "user": user or {}}
    return {"status": status}


def fetch_user(sess=None):
    try:
        s = sess or account_session()
        if not s:
            return None
        r = s.get(PASSPORT + "/passport/account/info/v2/",
                  params=_params(), timeout=15)
        d = (r.json() or {}).get("data") or {}
        name = d.get("name") or d.get("screen_name")
        if name:
            return {"name": name,
                    "avatar": d.get("avatar_url") or d.get("avatar") or ""}
    except Exception:
        pass
    return None


def _save(cookies, user, sid=None):
    p = _path(sid)
    if not p:
        return
    data = {"cookies": cookies, "user": user, "saved_at": int(time.time())}
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


def load_account(sid=None):
    p = _path(sid)
    if not p:
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def account_session(sid=None):
    """用落盘的 cookies 重建 session (cookie 无域限制, 可发往任意 host)。"""
    a = load_account(sid)
    if not a:
        return None
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    for k, v in (a.get("cookies") or {}).items():
        s.cookies.set(k, v)
    return s


def logout(sid=None):
    p = _path(sid)
    if not p:
        return
    try:
        os.remove(p)
    except OSError:
        pass


# ---- 观看历史同步 (reading.snssdk.com, 需登录态+签名) ----
def _signed_call(method, path, body=None, extra_query=None, sid=None):
    import hashlib
    import hongguo as H
    acc = load_account(sid)
    if not acc:
        raise RuntimeError("未登录")
    headers = dict(H.CFG["session_headers"])
    headers["cookie"] = "; ".join(f"{k}={v}" for k, v in acc["cookies"].items())
    headers["content-type"] = "application/json; charset=utf-8"
    url = H.build_url(path, extra_query).replace(H.HOST, "reading.snssdk.com")
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        headers["x-ss-stub"] = hashlib.md5(data).hexdigest().upper()
    headers.update(H.sign(url, headers))
    r = requests.request(method, url, data=data, headers=headers, timeout=20)
    return r.json()


def push_history(series_id, ep=0, position_ms=0, sid=None):
    """上报观看记录: book_id=series_id(整数!), vid_index=集号, current_play_position=毫秒"""
    body = {"update_datas": [{
        "book_id": int(series_id),
        "read_timestamp_ms": int(time.time() * 1000),
        "vid_index": int(ep),
        "current_play_position": int(position_ms),
    }]}
    j = _signed_call("POST", "/reading/bookapi/read_history/update/v", body, sid=sid)
    return j.get("code") == 0


def pull_history(count=50, sid=None):
    """拉取账号观看历史"""
    j = _signed_call("GET", "/reading/bookapi/read_history/list/v",
                     extra_query={"count": str(count)}, sid=sid)
    return j.get("data") or {}

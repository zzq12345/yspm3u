#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

# ---------------------------------------------------------------------------
# 常量定义
# ---------------------------------------------------------------------------

AK = "0123456789abcdef"  # AES 密钥

CLOUD_GET_URL = "https://api.cctv.cn/cctvmobile/cloud/get"
CLOUD_REGISTER_URL = "https://api.cctv.cn/cctvmobile/cloud/register"
APP_START_URL = "https://api.cctv.cn/cctvapp/app/start"
LIVE_V1_01_URL = "https://api.cctv.cn/cctvapp/live/v1/getPlayUrl"
LIVE_V1_02_URL = "https://api.cctv.cn/cctvapp/live/v1/getPlayUrl02"
VDN_GETSTREAM_URL = "https://vdn.live.cntv.cn/api2/live/getstream.action"

CHANNEL_LIST = {
    "cctv5": "cctv5",
    "cctv5p": "cctv5plus",
    "cctv164k": "cctv16_4k",
    "cctv4k": "cctv4k",
    "cctv8k": "cctv8k",
}

CHANNEL_NAMES_MAP = {
    "cctv5": "CCTV-5 体育",
    "cctv5p": "CCTV-5+ 体育赛事",
    "cctv164k": "CCTV-16 4K 奥林匹克",
    "cctv4k": "CCTV-4K 超高清",
    "cctv8k": "CCTV-8K 超高清",
}

# ---------------------------------------------------------------------------
# 异常与数据结构声明
# ---------------------------------------------------------------------------

class YsptpError(Exception):
    pass

@dataclass
class DeviceProfile:
    android_id: str = "1234567890abcdef"
    mac: str = "02:00:00:00:00:00"
    hardware: str = "qcom"
    board: str = "msm8998"
    brand: str = "Xiaomi"
    device: str = "sagit"
    manufacturer: str = "Xiaomi"
    model: str = "MI 6"
    product: str = "sagit"
    resolution: str = "1920x1080"

@dataclass
class DeviceState:
    profile: DeviceProfile = field(default_factory=DeviceProfile)
    x_uid: str = ""
    cloud_guid: str = ""

@dataclass
class Identity:
    headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class AppStartResult:
    session_key: str

@dataclass
class Live01Result:
    live_url: str
    rate: str
    rate_name: str

@dataclass
class VdnGetStreamResult:
    final_url: str
    app_sign: str
    app_random_str: str

# ---------------------------------------------------------------------------
# HTTP 客户端封装
# ---------------------------------------------------------------------------

class HttpResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="ignore")

class HttpClient:
    def __init__(self, timeout: float = 10.0, insecure_tls: bool = True):
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if insecure_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def post_bytes(self, url: str, headers: Dict[str, str], body: bytes) -> HttpResponse:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return HttpResponse(resp.status, resp.read())
        except urllib.error.HTTPError as e:
            return HttpResponse(e.code, e.read())
        except Exception as e:
            raise YsptpError(f"HTTP POST 失败: {e}")

    def post_form(self, url: str, headers: Dict[str, str], params: List[Tuple[str, str]]) -> HttpResponse:
        encoded_body = urllib.parse.urlencode(params).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self.post_bytes(url, headers, encoded_body)

# ---------------------------------------------------------------------------
# 加密与辅助工具类
# ---------------------------------------------------------------------------

def current_time_ms() -> int:
    return int(time.time() * 1000)

def compact_json_bytes(obj: dict, sort_keys: bool = False) -> bytes:
    return json.dumps(obj, sort_keys=sort_keys, separators=(',', ':')).encode('utf-8')

def extract_guid(res_json: dict) -> str:
    return res_json.get("data", {}).get("guid", "") or res_json.get("guid", "")

def fresh_headers(base: Dict[str, str], content_type: str = "") -> Dict[str, str]:
    headers = dict(base)
    headers["User-Agent"] = "cctv_app_tv"
    if content_type:
        headers["Content-Type"] = content_type
    return headers

def default_device_state() -> DeviceState:
    return DeviceState()

def build_identity(profile: DeviceProfile, app_channel: str, version: str) -> Identity:
    return Identity(headers={"User-Agent": "cctv_app_tv"})

def build_app_start_body(profile: DeviceProfile, x_uid: str, app_channel: str, version: str, now_ms: int) -> dict:
    return {
        "androidId": profile.android_id,
        "appChannel": app_channel,
        "appVersion": version,
        "deviceModel": profile.model,
        "timestamp": now_ms,
    }

def compute_vdn_code(ak: str) -> Tuple[str, str]:
    rand_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10))
    import hashlib
    sign = hashlib.md5((ak + rand_str).encode('utf-8')).hexdigest()
    return sign, rand_str

def build_vdn_appcommon(version: str) -> str:
    return json.dumps({"app_version": version, "platform": "android_tv"}, separators=(',', ':'))

def aes_gcm_encrypt_b64(text: str, key_str: str) -> str:
    if AESGCM is None:
        raise YsptpError("缺少依赖库 'cryptography'，请先运行: pip install cryptography")
    key = key_str.encode('utf-8').ljust(16, b'\0')[:16]
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
    return base64.b64encode(nonce + ct).decode('utf-8')

def aes_gcm_decrypt_b64(b64_str: str, key_str: str) -> str:
    if AESGCM is None:
        raise YsptpError("缺少依赖库 'cryptography'，请先运行: pip install cryptography")
    data = base64.b64decode(b64_str)
    nonce = data[:12]
    ct = data[12:]
    key = key_str.encode('utf-8').ljust(16, b'\0')[:16]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode('utf-8')

def channels() -> List[Tuple[str, str]]:
    return list(CHANNEL_LIST.items())

def channel_by_name(name: str) -> Optional[str]:
    return CHANNEL_LIST.get(name.lower())

def log_channel_ready(title: str) -> None:
    print(f"[OK] {title} 解析成功", file=sys.stderr)

# ---------------------------------------------------------------------------
# API 请求与频道解析逻辑
# ---------------------------------------------------------------------------

def cloud_get_device(client: HttpClient, identity: Identity, state: DeviceState) -> str:
    headers = fresh_headers(identity.headers, "application/json; charset=utf-8")
    body = compact_json_bytes({
        "android_id": state.profile.android_id,
        "mac": state.profile.mac,
        "model": state.profile.model,
    }, False)
    resp = client.post_bytes(CLOUD_GET_URL, headers, body)
    if resp.status == 200:
        try:
            return extract_guid(json.loads(resp.text()))
        except Exception:
            pass
    return ""

def cloud_register_device(client: HttpClient, identity: Identity, state: DeviceState) -> str:
    headers = fresh_headers(identity.headers, "application/json; charset=utf-8")
    body = compact_json_bytes({
        "android_id": state.profile.android_id,
        "mac": state.profile.mac,
        "hardware": state.profile.hardware,
        "board": state.profile.board,
        "brand": state.profile.brand,
        "device": state.profile.device,
        "manufacturer": state.profile.manufacturer,
        "model": state.profile.model,
        "product": state.profile.product,
        "resolution": state.profile.resolution,
    }, False)
    resp = client.post_bytes(CLOUD_REGISTER_URL, headers, body)
    if resp.status == 200:
        try:
            return extract_guid(json.loads(resp.text()))
        except Exception:
            pass
    return ""

def app_start(client: HttpClient, identity: Identity, state: DeviceState, version: str = "1.0.0") -> AppStartResult:
    now_ms = current_time_ms()
    payload = build_app_start_body(state.profile, state.x_uid, "cctv_app_tv", version, now_ms)
    enc_text = aes_gcm_encrypt_b64(json.dumps(payload, sort_keys=True, separators=(',', ':')), AK)
    
    headers = fresh_headers(identity.headers, "text/plain; charset=utf-8")
    resp = client.post_bytes(APP_START_URL, headers, enc_text.encode('utf-8'))
    if resp.status != 200:
        raise YsptpError(f"app/start http {resp.status}")
    
    dec_text = aes_gcm_decrypt_b64(resp.text().strip('"'), AK)
    res_json = json.loads(dec_text)
    session_key = res_json.get("data", {}).get("sessionKey", "") or res_json.get("sessionKey", "")
    if not session_key:
        raise YsptpError("app/start session_key missing")
    return AppStartResult(session_key=session_key)

def fetch_live_v1(client: HttpClient, identity: Identity, session_key: str, live_id: str) -> Live01Result:
    req_data = {
        "appChannel": "cctv_app_tv",
        "channelId": live_id,
        "deviceType": "TV",
        "sessionKey": session_key
    }
    enc_text = aes_gcm_encrypt_b64(json.dumps(req_data, sort_keys=True, separators=(',', ':')), AK)
    headers = fresh_headers(identity.headers, "text/plain; charset=utf-8")
    
    resp = client.post_bytes(LIVE_V1_01_URL, headers, enc_text.encode('utf-8'))
    if resp.status != 200:
        resp = client.post_bytes(LIVE_V1_02_URL, headers, enc_text.encode('utf-8'))
        if resp.status != 200:
            raise YsptpError(f"live/v1 http {resp.status}")
            
    dec_text = aes_gcm_decrypt_b64(resp.text().strip('"'), AK)
    data = json.loads(dec_text).get("data", {})
    
    live_url = data.get("playUrl", "") or data.get("liveUrl", "")
    rates = data.get("rateUrl", [])
    rate, rate_name = "", ""
    if rates:
        rate = rates[0].get("rate", "")
        rate_name = rates[0].get("rateName", "")
        if not live_url:
            live_url = rates[0].get("url", "")
            
    if not live_url:
        raise YsptpError("live/v1 no live url found")
        
    return Live01Result(live_url=live_url, rate=rate, rate_name=rate_name)

def fetch_vdn_stream(client: HttpClient, identity: Identity, state: DeviceState, live_01: Live01Result, version: str = "1.0.0") -> VdnGetStreamResult:
    app_sign, app_random_str = compute_vdn_code(AK)
    params = [
        ("appcommon", build_vdn_appcommon(version)),
        ("url", live_01.live_url),
        ("rate", live_01.rate),
        ("uid", state.profile.android_id),
        ("app_sign", app_sign),
        ("app_random_str", app_random_str)
    ]
    headers = fresh_headers(identity.headers, "application/x-www-form-urlencoded")
    resp = client.post_form(VDN_GETSTREAM_URL, headers, params)
    if resp.status != 200:
        raise YsptpError(f"vdn getstream http {resp.status}")
        
    data = json.loads(resp.text())
    url = data.get("url", "") or data.get("data", {}).get("url", "")
    if not url:
        raise YsptpError("vdn stream url missing")
    return VdnGetStreamResult(final_url=url, app_sign=app_sign, app_random_str=app_random_str)

def resolve_channel_m3u8(client: HttpClient, state: DeviceState, identity: Identity, channel_name: str) -> str:
    live_id = channel_by_name(channel_name)
    if not live_id:
        raise YsptpError(f"未知频道: {channel_name}")
        
    guid = cloud_get_device(client, identity, state)
    if not guid:
        guid = cloud_register_device(client, identity, state)
    state.cloud_guid = guid
    
    app_res = app_start(client, identity, state)
    live_res = fetch_live_v1(client, identity, app_res.session_key, live_id)
    vdn_res = fetch_vdn_stream(client, identity, state, live_res)
    return vdn_res.final_url

# ---------------------------------------------------------------------------
# M3U 导出逻辑
# ---------------------------------------------------------------------------

def export_m3u(output_file: str = "live.m3u") -> None:
    client = HttpClient(timeout=10.0, insecure_tls=True)
    state = default_device_state()
    identity = build_identity(state.profile, "cctv_app_tv", "1.0.0")
    
    m3u_lines = ["#EXTM3U"]
    
    print("开始解析频道列表并生成 M3U 文件...", file=sys.stderr)
    for ch_code, _live_id in channels():
        ch_title = CHANNEL_NAMES_MAP.get(ch_code, ch_code.upper())
        try:
            m3u8_url = resolve_channel_m3u8(client, state, identity, ch_code)
            m3u_lines.append(f'#EXTINF:-1 tvg-id="{ch_code}" tvg-name="{ch_title}" group-title="央视频",{ch_title}')
            m3u_lines.append('#EXTVLCOPT:http-user-agent=cctv_app_tv')
            m3u_lines.append('#EXTVLCOPT:http-referrer=https://api.cctv.cn')
            m3u_lines.append(m3u8_url)
            log_channel_ready(ch_title)
        except Exception as e:
            print(f"获取 {ch_title} 失败: {e}", file=sys.stderr)
            
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(m3u_lines) + "\n")
    print(f"M3U 导出完成: {output_file}", file=sys.stderr)

# ---------------------------------------------------------------------------
# 本地 HTTP 代理服务器服务 (如果需要)
# ---------------------------------------------------------------------------

class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        channel = self.path.lstrip('/')
        if not channel:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"YSPTP Server is running. Use /cctv5 or --export-m3u.")
            return

        client = HttpClient()
        state = default_device_state()
        identity = build_identity(state.profile, "cctv_app_tv", "1.0.0")

        try:
            m3u8_url = resolve_channel_m3u8(client, state, identity, channel)
            self.send_response(302)
            self.send_header("Location", m3u8_url)
            self.end_headers()
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Error: {e}".encode("utf-8"))

# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="ysptp CCTV live m3u8 proxy & M3U exporter")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=18766, help="监听端口")
    parser.add_argument("--export-m3u", type=str, help="导出 M3U 文件路径 (例: live.m3u)")
    args = parser.parse_args()

    if args.export_m3u:
        export_m3u(args.export_m3u)
        sys.exit(0)

    server = HTTPServer((args.host, args.port), ProxyHandler)
    print(f"代理服务器启动于 http://{args.host}:{args.port}")
    server.serve_forever()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ...（保留原 ysptp.py 头部导入、常量与加密算法部分）...

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
        raise YsptpError(f"unknown channel: {channel_name}")
        
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

CHANNEL_NAMES_MAP = {
    "cctv5": "CCTV-5 体育",
    "cctv5p": "CCTV-5+ 体育赛事",
    "cctv164k": "CCTV-16 4K 奥林匹克",
    "cctv4k": "CCTV-4K 超高清",
    "cctv8k": "CCTV-8K 超高清",
}

def export_m3u(output_file: str = "live.m3u") -> None:
    client = HttpClient(timeout=10.0, insecure_tls=True)
    state = default_device_state()
    identity = build_identity(state.profile, "cctv_app_tv", "1.0.0")
    
    m3u_lines = ["#EXTM3U"]
    
    print("开始获取并生成 M3U 播放列表...", file=sys.stderr)
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
    print(f"M3U 文件保存成功: {output_file}", file=sys.stderr)

# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="ysptp CCTV live m3u8 proxy & M3U exporter")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=18766, help="Listen port")
    parser.add_argument("--export-m3u", type=str, help="直接生成 M3U 播放列表文件并退出 (例: live.m3u)")
    args = parser.parse_args()

    if args.export_m3u:
        export_m3u(args.export_m3u)
        sys.exit(0)

    # 若未指定 --export-m3u 则继续运行原代理 HTTP 服务逻辑...

if __name__ == "__main__":
    main()

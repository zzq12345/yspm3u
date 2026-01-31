import base64
import ctypes
import os
import random
import struct
import time
import uuid
import requests
from construct import Struct, Int16ub, Int32ub, Bytes, this
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

# （所有原有的 struct、加密函數、ckey42 等保持不變，以下僅展示修改部分）

app = FastAPI()

@app.get("/ysp")
def ysp(cnlid: str, livepid: str, defn: str = "auto", guid: str = None, app_version: str = "3.2.2.23730"):
    try:
        url = "https://liveinfo.ysp.cctv.cn"
        if not guid:
            guid = RandomHexStr(32)
            
        current_time = int(time.time())
        
        params = {
            "guid": guid,
            "device": "iPhone",
            "livepid": livepid,
            "platform": "4330403",
            "newplatform": "4330403",
            "getpreviewinfo": "0",
            "uhd_flag": "2",
            "spdrm": "2",
            "adjust": "1",
            "spdynamicrange": "1",
            "appVer": "V8.22.1035.3031",
            "lang": "zh_TW",
            "encryptVer": "4.2",
            "spaudio": "1",
            "spflvaudio": "1",
            "spvcode": "MSgzMDoxMDgwLDYwOjEwODAsOTA6MTA4MHwzMDoxMDgwLDYwOjEwODAsOTA6MTA4MCk7MigzMDoxMDgwLDYwOjEwODAsOTA6MTA4MHwzMDoxMDgwLDYwOjEwODAsOTA6MTA4MCk=",
            "spflv": "1",
            "sphdrfps": "0",
            "spacode": "7",
            "system": "1",
            "spdemuxer": "6",
            "defn": defn,
            "hevclv": "26",
            "stream": "1",
            "caplv": "1",
            "newnettype": "1",
            "fntick": current_time - 100,
            "flowid": f"{RandomHexStr(8)}-{RandomHexStr(4)}-{RandomHexStr(4)}-{RandomHexStr(4)}-{RandomHexStr(12)}_4330403",
            "qqlog": "0",
            "sysver": "ios15.8.5",
            "qq": "0",
            "openid": "",
            "livequeue": "0",
            "sdtfrom": "v3021",
            "cnlid": cnlid,
            "sphttps": "0",
            "logintype": "3",
            "nettype": "1",
            "playbacktime": "0",
            "app_version": app_version,
            "cmd": "2",
            "userid": "",
            "atime": "120",
            "head_key_traceid": "402",
        }
        
        headers = {
            'User-Agent': "qqlive",
            'Accept': '*/*',
            'Accept-Language': 'zh-TW,zh-Hant;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'head_key_traceid': '402',
        }
        
        Platform = params['platform']
        Timestamp = current_time
        appVer = params['appVer']
        Sdtfrom = params['sdtfrom']
        # 使用 cnlid 作為 vid 參數（原邏輯）
        ckey = ckey42(Platform, Timestamp, Sdtfrom, cnlid, guid, appVer)
        params.update({"cKey": ckey})
        
        response = requests.get(url, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()
        
        # 統一處理返回（不再直接 Redirect）
        formats = data.get('formats', [])
        playurl = data.get('playurl', '')
        vkey = data.get('vkey', '')  # 有時需要 vkey
        
        # 解碼 unicode_escape（\u0026 → &）
        if playurl:
            playurl = playurl.encode('utf-8').decode('unicode_escape')
        
        backurls = []
        for item in data.get('backurl_list', []):
            url = item.get('url', '')
            if url:
                url = url.encode('utf-8').decode('unicode_escape')
                backurls.append(url)
        
        result = {
            "status": "success",
            "defn": defn,
            "formats": formats,
            "playurl": playurl,          # 主播放地址（可能為默認最高清晰度）
            "backurls": backurls,        # 備用 CDN 地址（主地址緩衝時可切換）
            "vkey": vkey,
            "raw_data_keys": list(data.keys())
        }
        
        return JSONResponse(content=result)
            
    except Exception as e:
        return JSONResponse(content={
            "status": "error",
            "error": str(e),
            "traceback": str(e.__traceback__) if hasattr(e, '__traceback__') else None
        })

@app.get("/test")
def test():
    """測試接口，驗證 CKey 生成"""
    Platform = "4330403"
    Timestamp = int(time.time())
    cnlid = "2024075401"
    guid = RandomHexStr(32)
    ckey = ckey42(Platform, Timestamp, "v3021", cnlid, guid, "V8.22.1035.3031")
    return {
        "ckey_length": len(ckey),
        "ckey_prefix": ckey[:50],
        "guid": guid,
        "timestamp": Timestamp
    }

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8080)

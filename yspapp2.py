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
from fastapi.responses import RedirectResponse, JSONResponse
import uvicorn

int16_str_struct = Struct(
    "length" / Int16ub,
    "value" / Bytes(this.length)
)
signature_uid_struct = Struct(
    "signature" / int16_str_struct,
    "uid" / int16_str_struct
)
int32_str_struct =Struct(
    "length" / Int32ub,
    "value" / Bytes(this.length)
)

ckey_struct = Struct(
    "header" / Bytes(12),
    "Platform" / Bytes(4),
    "signature" / Bytes(4),
    "Timestamp" / Bytes(4),
    "Sdtfrom" / int16_str_struct,
    "randFlag" / int16_str_struct,
    "appVer" / int16_str_struct,
    "vid" / int16_str_struct,
    "guid" / int16_str_struct,
    "part1" / Int32ub,
    "isDlna" / Int32ub,
    "uid" / int16_str_struct,
    "bundleID" / int16_str_struct,
    "uuid4" / int16_str_struct,
    "bundleID1"/ int16_str_struct,
    "ckeyVersion" / int16_str_struct,
    "packageName" / int16_str_struct,
    "platform_str" / int16_str_struct,
    "ex_json_bus"/ int16_str_struct,
    "ex_json_vs" / int16_str_struct,
    "ck_guard_time" / int16_str_struct
)
ckey42_struct =Struct(
    "length" / Int16ub,
    "value" / Bytes(this.length)
)
DELTA = 0x9e3779b9
ROUNDS = 16
LOG_ROUNDS = 4
SALT_LEN = 2
ZERO_LEN = 7
TEA_CKEY =bytes.fromhex('59b2f7cf725ef43c34fdd7c123411ed3')
XOR_KEY = [0x84, 0x2E, 0xED, 0x08, 0xF0, 0x66, 0xE6, 0xEA, 0x48, 0xB4, 0xCA, 0xA9, 0x91, 0xED, 0x6F, 0xF3];
STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
CUSTOM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-='

class Size_t(object):
    value = 0

    def __init__(self, value):
        self.value = value

def encrypt(key: bytes, sIn: bytes, iLength: int, buffer: bytearray) -> None:
    outlen: Size_t = Size_t(oi_symmetry_encrypt2_len(iLength))
    oi_symmetry_encrypt2(sIn, iLength, key, buffer, outlen)
    while len(buffer) > outlen.value:
        buffer.pop()

def decrypt(key: bytes, sIn: bytes, iLength: int, buffer: bytearray) -> bool:
    outlen: Size_t = Size_t(iLength)
    if not oi_symmetry_decrypt2(sIn, iLength, key, buffer, outlen):
        return False
    while len(buffer) > outlen.value:
        buffer.pop()
    return True

def TeaEncryptECB(pInBuf: bytes, pKey: bytes, pOutBuf: bytearray) -> None:
    k = list()
    pOutBuf.clear()
    y, z = struct.unpack("!II", pInBuf[:8])
    for i in struct.unpack("!IIII", pKey):
        k.append(i)
    sum = 0
    for i in range(ROUNDS):
        sum += DELTA
        sum = ctypes.c_uint32(sum).value
        y += ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1])
        y = ctypes.c_uint32(y).value
        z += ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3])
        z = ctypes.c_uint32(z).value
    for i in struct.pack("!II", y, z):
        pOutBuf.append(i)

def TeaDecryptECB(pInBuf: bytes, pKey: bytes, pOutBuf: bytearray) -> None:
    k = list()
    pOutBuf.clear()
    y, z = struct.unpack("!II", pInBuf[:8])
    for i in struct.unpack("!IIII", pKey):
        k.append(i)
    sum = ctypes.c_uint32(DELTA << LOG_ROUNDS).value
    for i in range(ROUNDS):
        z -= ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3])
        z = ctypes.c_uint32(z).value
        y -= ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1])
        y = ctypes.c_uint32(y).value
        sum -= DELTA
    for i in struct.pack("!II", y, z):
        pOutBuf.append(i)

def oi_symmetry_encrypt2_len(nInBufLen: int) -> int:
    nPadSaltBodyZeroLen = nInBufLen
    nPadSaltBodyZeroLen += 1 + SALT_LEN + ZERO_LEN
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen
    return nPadSaltBodyZeroLen + nPadlen

def oi_symmetry_encrypt2(pInBuf: bytes, nInBufLen: int, pKey: bytes, pOutBuf: bytearray, pOutBufLen: Size_t) -> None:
    nPadSaltBodyZeroLen = nInBufLen
    nPadSaltBodyZeroLen = nPadSaltBodyZeroLen + 1 + SALT_LEN + ZERO_LEN
    nPadlen = nPadSaltBodyZeroLen % 8
    if nPadlen:
        nPadlen = 8 - nPadlen
    src_buf = bytearray([0] * 8)
    src_buf[0] = (random.randint(0, 255) & 0xf8) | nPadlen
    src_i = 1
    while nPadlen:
        src_buf[src_i] = random.randint(0, 255)
        src_i += 1
        nPadlen -= 1
    iv_plain = bytearray([0] * 8)
    iv_crypt = bytearray(iv_plain)
    pOutBufLen.value = 0
    i = 1
    while i <= SALT_LEN:
        if src_i < 8:
            src_buf[src_i] = random.randint(0, 255)
            src_i += 1
            i += 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]
            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)
            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]
            for j in range(8):
                iv_plain[j] = src_buf[j]
            src_i = 0
            iv_crypt = bytearray(temp_pOutBuf)
            pOutBufLen.value += 8
            pOutBuf += temp_pOutBuf
    pInBufIndex = 0
    while nInBufLen:
        if src_i < 8:
            src_buf[src_i] = pInBuf[pInBufIndex]
            pInBufIndex += 1
            src_i += 1
            nInBufLen -= 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]
            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)
            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]
            for j in range(8):
                iv_plain[j] = src_buf[j]
            src_i = 0
            iv_crypt = bytearray(temp_pOutBuf)
            pOutBufLen.value += 8
            pOutBuf += temp_pOutBuf
    i = 1
    while i <= ZERO_LEN:
        if src_i < 8:
            src_buf[src_i] = 0
            src_i += 1
            i += 1
        if src_i == 8:
            for j in range(8):
                src_buf[j] ^= iv_crypt[j]
            temp_pOutBuf = bytearray()
            TeaEncryptECB(src_buf, pKey, temp_pOutBuf)
            for j in range(8):
                temp_pOutBuf[j] ^= iv_plain[j]
            for j in range(8):
                iv_plain[j] = src_buf[j]
            src_i = 0
            iv_crypt = temp_pOutBuf
            pOutBufLen.value += 8
            pOutBuf += temp_pOutBuf

def oi_symmetry_decrypt2(pInBuf: bytes, nInBufLen: int, pKey: bytes, pOutBuf: bytearray, pOutBufLen: Size_t) -> bool:
    dest_buf = bytearray()
    zero_buf = bytearray()
    nBufPos = 0
    if (nInBufLen % 8) or (nInBufLen < 16):
        return False
    TeaDecryptECB(pInBuf, pKey, dest_buf)
    nPadLen = dest_buf[0] & 0x7
    i = nInBufLen - 1
    i = i - nPadLen - SALT_LEN - ZERO_LEN
    if (pOutBufLen.value < i) or (i < 0):
        return False
    pOutBufLen.value = i
    for i in range(8):
        zero_buf.append(0)
    iv_pre_crypt = bytearray(zero_buf)
    iv_cur_crypt = bytearray(pInBuf)
    pInBuf = pInBuf[8:]
    nBufPos += 8
    dest_i = 1
    dest_i += nPadLen
    i = 1
    while i <= SALT_LEN:
        if dest_i < 8:
            dest_i += 1
            i += 1
        elif dest_i == 8:
            iv_pre_crypt = bytearray(iv_cur_crypt)
            iv_cur_crypt = bytearray(pInBuf)
            for j in range(8):
                if nBufPos + j >= nInBufLen:
                    return False
                dest_buf[j] ^= pInBuf[j]
            TeaDecryptECB(bytes(dest_buf), pKey, dest_buf)
            pInBuf = pInBuf[8:]
            nBufPos += 8
            dest_i = 0
    nPlainLen = pOutBufLen.value
    while nPlainLen:
        if dest_i < 8:
            pOutBuf.append(dest_buf[dest_i] ^ iv_pre_crypt[dest_i])
            dest_i += 1
            nPlainLen -= 1
        elif dest_i == 8:
            iv_pre_crypt = bytearray(iv_cur_crypt)
            iv_cur_crypt = bytearray(pInBuf)
            for j in range(8):
                if nBufPos + j >= nInBufLen:
                    return False
                dest_buf[j] ^= pInBuf[j]
            TeaDecryptECB(bytes(dest_buf), pKey, dest_buf)
            pInBuf = pInBuf[8:]
            nBufPos += 8
            dest_i = 0
    i = 1
    while i <= ZERO_LEN:
        if dest_i < 8:
            if dest_buf[dest_i] ^ iv_pre_crypt[dest_i]:
                return False
            dest_i += 1
            i += 1
        elif dest_i == 8:
            iv_pre_crypt = bytearray(iv_cur_crypt)
            iv_cur_crypt = bytearray(pInBuf)
            for j in range(8):
                if nBufPos + j >= nInBufLen:
                    return False
                dest_buf[j] ^= pInBuf[j]
            TeaDecryptECB(bytes(dest_buf), pKey, dest_buf)
            pInBuf += 8
            nBufPos += 8
            dest_i = 0
    return True

def tc_tea_encrypt(keys: bytes, message: bytes) -> bytes:
    data = bytearray()
    encrypt(keys, message, len(message), data)
    return bytes(data)

def tc_tea_decrypt(keys: bytes, message: bytes) -> bytes:
    data = bytearray()
    if decrypt(keys, message, len(message), data):
        return bytes(data)
    else:
        raise Exception('解密失败')

def CalcSignature(decArray):
    signature = 0
    for byte in decArray:
        signature = (0x83 * signature + byte)
    return signature& 0x7FFFFFFF

def RandomHexStr(length):
    return ''.join(random.choice('0123456789ABCDEF') for _ in range(length))

def XOR_Array(byteArray):
    retArray = bytearray(byteArray)
    for i in range(len(retArray)):
        retArray[i] ^= XOR_KEY[i & 0xF]
    return retArray

def custom_encode(text):
    encoded_data = base64.b64encode(text)
    encoded_str = encoded_data.decode('utf-8')
    translated_str = encoded_str.translate(str.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET))
    return translated_str

def custom_decode(text):
    text =text if len(text) % 4 == 0 else text + '=' * (4 - len(text) % 4)
    data = base64.b64decode(text.translate(str.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)))
    return data

def create_str_data(value):
    if value is None:
        value = ""
    if isinstance(value, int):
        value = str(value)
    return {"length": len(value), "value": value.encode('utf-8')}

def ckey42(Platform, Timestamp, Sdtfrom = "fcgo",vid="600002264", guid=None, appVer="V8.22.1035.3031"):
    header = b'\x00\x00\x00\x42\x00\x00\x00\x04\x00\x00\x04\xd2'
    data = {
        "header": header,
        "Platform": int(Platform).to_bytes(4, 'big'),
        "signature": b'\x00\x00\x00\x00',
        "Timestamp": Timestamp.to_bytes(4, 'big'),
        "Sdtfrom": create_str_data(Sdtfrom),
        "randFlag": create_str_data(
            base64.b64encode(os.urandom(18)).decode()
        ),
        "appVer": create_str_data(appVer),
        "vid": create_str_data(vid),
        "guid": create_str_data(guid),
        "part1": 1,
        "isDlna": 1,
        "uid": create_str_data("2622783A"),
        "bundleID": create_str_data("nil"),
        "uuid4": create_str_data(str(uuid.uuid4())),
        "bundleID1": create_str_data("nil"),
        "ckeyVersion": create_str_data("v0.1.000"),
        "packageName": create_str_data("com.cctv.yangshipin.app.iphone"),
        "platform_str": create_str_data(str(Platform)),
        "ex_json_bus": create_str_data("ex_json_bus"),
        "ex_json_vs": create_str_data("ex_json_vs"),
        "ck_guard_time": create_str_data(RandomHexStr(66)),
    }
    Buffer = ckey_struct.build(data)
    BufferLenHex = hex(len(Buffer))[2:].zfill(4)
    BufferHead = [int(BufferLenHex[i:i+2], 16) for i in range(0, len(BufferLenHex), 2)]
    Buffer = BufferHead + list(Buffer)
    encrypt_data = tc_tea_encrypt(TEA_CKEY, bytes(Buffer))
    encrypt_data=bytearray(encrypt_data)
    CheckSum=CalcSignature(Buffer)
    CheckSumBytes = struct.pack('>I', CheckSum)
    encrypt_data.extend(CheckSumBytes)
    result = XOR_Array(encrypt_data)
    return "--01"+custom_encode(result).replace('=','')

app=FastAPI()

def get_china_ip():
    """生成一个随机的中国大陆IP地址"""
    # 中国大陆IP范围示例（部分主要IP段）
    china_ip_ranges = [
        (36, 63),     # 36.0.0.0 - 36.255.255.255
        (58, 63),     # 58.0.0.0 - 58.255.255.255
        (59, 63),     # 59.0.0.0 - 59.255.255.255
        (60, 63),     # 60.0.0.0 - 60.255.255.255
        (61, 63),     # 61.0.0.0 - 61.255.255.255
        (106, 107),   # 106.0.0.0 - 107.255.255.255
        (110, 111),   # 110.0.0.0 - 111.255.255.255
        (112, 115),   # 112.0.0.0 - 115.255.255.255
        (116, 119),   # 116.0.0.0 - 119.255.255.255
        (120, 127),   # 120.0.0.0 - 127.255.255.255
        (171, 175),   # 171.0.0.0 - 175.255.255.255
        (183, 191),   # 183.0.0.0 - 191.255.255.255
        (202, 203),   # 202.0.0.0 - 203.255.255.255
        (210, 211),   # 210.0.0.0 - 211.255.255.255
        (218, 219),   # 218.0.0.0 - 219.255.255.255
        (220, 221),   # 220.0.0.0 - 221.255.255.255
        (222, 223),   # 222.0.0.0 - 223.255.255.255
    ]
    
    # 随机选择一个IP段
    first_octet_range = random.choice(china_ip_ranges)
    first_octet = random.randint(first_octet_range[0], first_octet_range[1])
    
    # 生成完整的IP地址
    ip = f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    return ip

@app.get("/ysp")
def ysp(cnlid: str, livepid: str, defn: str = "auto"):
    try:
        url = "https://liveinfo.ysp.cctv.cn"
        params ={
            "atime":"120",
            "livepid":  livepid,
            "cnlid":  cnlid,
            "appVer": "V8.22.1035.3031",
            "app_version": "300090",
            "caplv": "1",
            "cmd": "2",
            "defn":  defn,
            "device": "iPhone",
            "encryptVer": "4.2",
            "getpreviewinfo": "0",
            "hevclv": "33",
            "lang": "zh-Hans_JP",
            "livequeue": "0",
            "logintype": "1",
            "nettype": "1",
            "newnettype": "1",
            "newplatform": "4330403",
            "platform": "4330403",
            "playbacktime": "0",
            "sdtfrom": "v3021",
            "spacode": "23",
            "spaudio": "1",
            "spdemuxer": "6",
            "spdrm": "2",
            "spdynamicrange": "7",
            "spflv": "1",
            "spflvaudio": "1",
            "sphdrfps": "60",
            "sphttps": "0",
           "spvcode": "MSgzMDoyMTYwLDYwOjIxNjB8MzA6MjE2MCw2MDoyMTYwKTsyKDMwOjIxNjAsNjA6MjE2MHwzMDoyMTYwLDYwOjIxNjAp",
            "spvideo": "4",
            "stream": "1",
            "system": "1",
            "sysver": "ios18.2.1",
            "uhd_flag": "4",
        }
        
        # 生成一个中国大陆IP地址
        china_ip = get_china_ip()
        
        headers = {
            'User-Agent': "qqlive",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            # 添加IP相关的headers来模拟内地IP访问
            'X-Forwarded-For': china_ip,
            'X-Real-IP': china_ip,
            'X-Client-IP': china_ip,
            'CF-Connecting-IP': china_ip,  # CloudFlare的IP头
            'True-Client-IP': china_ip,    # Akamai的IP头
        }
        
        Platform = params['platform']
        Timestamp = int(time.time())
        appVer = params['appVer']
        Cnlid = params['cnlid']
        StaGuid = RandomHexStr(32)
        sdtfrom = 'dcgh'
        ckey=ckey42(Platform, Timestamp, sdtfrom, Cnlid, StaGuid, appVer)
        params.update({"cKey":ckey})
        
        # 设置请求超时时间
        timeout = (10, 30)  # 连接超时10秒，读取超时30秒
        
        # 发送请求，使用上面生成的headers
        response = requests.get(url, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()  # 如果响应状态码不是200，抛出异常
        
        data = response.json()
        
        if defn=="auto":
            formats=data.get('formats', [])
            return JSONResponse(content={"formats": formats})
        
        url=data.get('playurl')
        if not url:
            return {"error": "No playurl found in response"}
            
        return RedirectResponse(url=url)
        
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP请求失败: {str(e)}"}
    except ValueError as e:
        return {"error": f"JSON解析失败: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8080)

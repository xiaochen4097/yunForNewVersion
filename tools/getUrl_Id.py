import argparse
import configparser
import hashlib
import json
import os
from base64 import b64decode, b64encode
from urllib.parse import urlsplit

import requests
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

# 兼容 python tools/getUrl_Id.py 与 from tools.getUrl_Id import ... 两种入口
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONF = os.path.join(_REPO_ROOT, "config.ini")

# 公共学校目录：普通 JSON 接口（不是学校业务服务的 SM4 信封）
# 旧接口 http://sports.aiyyd.com:9001/api/app/schoolList 已不可用：连不上时响应体为空，
# b64decode("") 得到空 bytes，gmssl 的 pkcs7_unpadding 会抛 IndexError: list index out of range，
# 于是账号密码登录在查学校这一步就崩了。改用 3.6.6 客户端使用的 9011 接口。
SCHOOL_DIRECTORY_URL = "https://sports.aiyyd.com:9011/api/app/lisshtcool"
# 目录服务会检查版本：不带 version 或版本过低会返回 code=500（版本过低）
SCHOOL_DIRECTORY_VERSION = "3.6.6"
DEFAULT_TIMEOUT = (8, 15)  # (连接超时, 读取超时)


def md5_encryption(data):
    md5 = hashlib.md5()  # 创建一个md5对象
    md5.update(data.encode('utf-8'))  # 使用utf-8编码数据
    return md5.hexdigest()  # 返回加密后的十六进制字符串


def encrypt_sm4(value, SM_KEY, isBytes = False):
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(SM_KEY, SM4_ENCRYPT)
    if not isBytes:
        encrypt_value = b64encode(crypt_sm4.crypt_ecb(value.encode("utf-8")))
    else:
        encrypt_value = b64encode(crypt_sm4.crypt_ecb(value))
    return encrypt_value.decode()


def decrypt_sm4(value, SM_KEY):
    """解密服务端返回的 SM4 密文；格式不对时抛出可读的 ValueError，而不是 IndexError。"""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        # 有的学校会把密文再包一层 JSON 引号，例如 '"xxxx=="'
        text = str(value or "").strip().strip('"').strip()
        if not text:
            raise ValueError("响应体为空（既不是密文也不是 JSON），请检查网络/代理后重试")
        try:
            raw = b64decode(text)
        except Exception as exc:
            raise ValueError(f"响应体不是合法的 Base64 密文：{exc}") from exc
    if not raw:
        # 这里就是 IndexError 的源头：空密文喂给 gmssl，pkcs7_unpadding 会取 data[-1]
        raise ValueError("密文解码后为空，说明服务端没有返回密文（常见于连不上服务端、走了失效的代理）")
    if len(raw) % 16 != 0:
        raise ValueError(f"密文长度 {len(raw)} 不是 16 的整数倍，响应不是 SM4 密文")
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(SM_KEY, SM4_DECRYPT)
    return crypt_sm4.crypt_ecb(raw)


def load_config(conf_path=None):
    path = conf_path or DEFAULT_CONF
    config = configparser.ConfigParser()
    if os.path.exists(path):
        config.read(path, encoding='utf-8')
    return config


def fetch_school_directory(transport=None, timeout=DEFAULT_TIMEOUT):
    """查询公共学校目录，返回学校记录列表（未登录、不带 token）。"""
    send = transport or requests.post
    try:
        response = send(
            url=SCHOOL_DIRECTORY_URL,
            data="",
            headers={
                "version": SCHOOL_DIRECTORY_VERSION,
                "platform": "android",
                "isApp": "app",
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )
    except Exception as exc:
        raise RuntimeError(
            f"无法访问学校目录 {SCHOOL_DIRECTORY_URL}（{type(exc).__name__}: {exc}）；"
            "请检查网络，关掉 VPN/抓包代理后重试"
        ) from exc
    if response.status_code != 200:
        raise RuntimeError(f"学校目录返回 HTTP {response.status_code}：{response.text[:120]!r}")
    try:
        payload = response.json()
    except Exception as exc:
        body = getattr(response, "text", "")
        raise RuntimeError(f"学校目录返回的不是 JSON：{str(body)[:120]!r}") from exc
    if not isinstance(payload, dict) or payload.get('code') != 200:
        code = payload.get('code') if isinstance(payload, dict) else None
        msg = payload.get('msg') if isinstance(payload, dict) else ""
        raise RuntimeError(f"学校目录返回 code={code} msg={msg}")
    rows = payload.get('data')
    if not isinstance(rows, list):
        raise RuntimeError("学校目录的 data 字段不是学校列表")
    return [row for row in rows if isinstance(row, dict)]


def getschool_Url_Id(schoolName, transport=None):
    """按学校全称精确匹配，返回 (schoolUrl, schoolId)；查不到返回 (None, None) 并说明原因。"""
    name = (schoolName or "").strip()
    if not name:
        print("学校名称不能为空。")
        return None, None
    try:
        rows = fetch_school_directory(transport)
    except Exception as exc:
        print(f"查询学校目录失败：{exc}")
        print("可以先在 config.ini 里手填 school_host 和 school_id（抓包获得），登录会直接使用它。")
        return None, None
    matches = [row for row in rows if (row.get('schoolName') or "").strip() == name]
    if not matches:
        print(f"未找到匹配的学校名称：{name}（要跟官方客户端里的学校全称完全一致）")
        print("已查询到 " + str(len(rows)) + " 所学校，可用 python tools/getUrl_Id.py --list 查看完整目录。")
        return None, None
    if len(matches) > 1:
        print(f"学校名称 {name} 在目录里有 {len(matches)} 条记录，无法自动选择，请手动填写 school_host 和 school_id。")
        return None, None
    row = matches[0]
    schoolUrl = (row.get('schoolUrl') or "").strip().rstrip('/')
    schoolId = row.get('schoolId')
    if not schoolUrl or schoolId is None or not str(schoolId).strip():
        print(f"学校 {name} 缺少有效的 schoolUrl/schoolId，无法使用。")
        return None, None
    parts = urlsplit(schoolUrl)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        print(f"学校 {name} 的 schoolUrl 不是 HTTP(S) 地址：{schoolUrl}")
        return None, None
    return schoolUrl, schoolId


def writeUrlToConfig(schoolUrl, schoolId, conf_path=None):
    if not schoolUrl or schoolId is None or not str(schoolId).strip():
        print("没有得到有效的学校地址/ID，config.ini 保持不变。")
        return
    path = conf_path or DEFAULT_CONF
    config = load_config(path)
    if not config.has_section("Yun"):
        config.add_section("Yun")
    current_school_host = config.get("Yun", "school_host", fallback="")
    current_school_id = config.get("Yun", "school_id", fallback="")
    if schoolUrl != current_school_host or str(schoolId) != current_school_id:
        print("schoolUrl:", schoolUrl)
        print("schoolId:", schoolId)
        config.set("Yun", "school_host", schoolUrl)
        config.set("Yun", "school_id", str(schoolId))
        with open(path, 'w', encoding='utf-8') as configfile:
            config.write(configfile)
    else:
        print("当前学校URL和ID与配置文件中的一致，无需更新。")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="查询云运动公共学校目录，获取 school_host / school_id")
    parser.add_argument("--list", action="store_true", help="打印完整学校目录（学校全称 + schoolId + schoolUrl）")
    parser.add_argument("--school", help="学校全称，精确匹配查询")
    parser.add_argument("--write", action="store_true", help="查询成功后写入 config.ini 的 school_host/school_id")
    parser.add_argument("--config", default=DEFAULT_CONF, help="配置文件路径，配合 --write 使用")
    args = parser.parse_args()

    if args.list:
        try:
            rows = fetch_school_directory()
        except Exception as exc:
            print(f"查询学校目录失败：{exc}")
            raise SystemExit(1)
        for row in sorted(rows, key=lambda r: str(r.get('schoolId'))):
            print(f"{row.get('schoolId'):>6}  {row.get('schoolName')}  {row.get('schoolUrl')}")
        raise SystemExit(0)

    schoolName = args.school or input("请输入学校名称：")
    url, schoolId = getschool_Url_Id(schoolName)
    if not url:
        raise SystemExit(1)
    print("schoolUrl:", url)
    print("schoolId:", schoolId)
    if args.write:
        writeUrlToConfig(url, schoolId, conf_path=args.config)
    else:
        print("仅查询，未修改配置；确认无误后加 --write 写入。")

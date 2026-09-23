import random
import time
from base64 import b64decode
import requests
import json
import configparser
import os
import sys

# tools 目录要进 sys.path 才能 import getUrl_Id
# （原来靠 tools/drift.py 里的 sys.path.append 副作用，main.py 一改导入顺序就会 ModuleNotFoundError）
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

from getUrl_Id import getschool_Url_Id, encrypt_sm4, decrypt_sm4, md5_encryption

DEFAULT_CONF = os.path.join(os.path.dirname(_TOOLS_DIR), 'config.ini')


def _write_conf(conf, path):
    with open(path, 'w', encoding='utf-8') as f:
        conf.write(f)


class Login():

    def main(conf_path=None):

        utc = int(time.time())

        path = conf_path or DEFAULT_CONF
        if not os.path.exists(path):
            print("配置文件不存在：" + path)
            return None

        #读取ini
        conf = configparser.ConfigParser()
        conf.read(path, encoding='utf-8')

        #判断[Login]是否存在
        if 'Login' not in conf.sections():
            conf.add_section('Login')
            conf.set('Login', 'username', '')
            conf.set('Login', 'password', '')
            _write_conf(conf, path)

        if 'Yun' not in conf.sections():
            print("配置文件 " + path + " 缺少 [Yun] 段，请参考 README 补全。")
            return None

        #判断school_id是否在[Yun]中
        if 'school_id' not in conf['Yun']:
            conf.set('Yun', 'school_id', '100')
            _write_conf(conf, path)

        #读取ini配置
        username = conf.get('Login', 'username') or input('未找到用户名，请输入用户名：')
        password = conf.get('Login', 'password') or input('未找到密码，请输入密码：')
        iniDeviceId = conf.get('User', 'device_id', fallback='')
        iniDeviceName = conf.get('User', 'device_name', fallback='')
        iniuuid = conf.get('User', 'uuid', fallback='')
        iniSysedition = conf.get('User', 'sys_edition', fallback='')
        appedition = conf.get('Yun', 'app_edition', fallback='3.6.6')
        platform = conf.get('Yun', 'platform', fallback='android')
        md5key = conf.get('Yun', 'md5key', fallback='')
        schoolName = conf.get('Yun','school_name', fallback='').strip() or input("未找到学校名称，请输入学校名称：")
        conf.set('Yun','school_name', schoolName)

        # 先查公共学校目录拿最新的 school_host/school_id；查不到就退回 config 里已有的值，
        # 不再因为查目录失败（旧接口已失效）在登录第一步就抛 IndexError
        schoolHost = conf.get('Yun', 'school_host', fallback='').strip().rstrip('/')
        schoolid = conf.get('Yun', 'school_id', fallback='').strip()
        url, scId = getschool_Url_Id(schoolName)
        if url and scId:
            conf.set('Yun', 'school_host', url)
            conf.set('Yun', 'school_id', str(scId))
            _write_conf(conf, path)
            schoolHost, schoolid = url.rstrip('/'), str(scId)
        elif schoolHost and schoolid:
            print("改用 config.ini 里已有的学校信息：" + schoolHost + "（school_id=" + schoolid + "）")
        else:
            print("学校目录查询失败，config.ini 里也没有 school_host/school_id，无法登录。")
            print("请检查网络（关掉 VPN/抓包代理）后重试，或按 README 抓包后手动填写这两个值。")
            return None

        # 不同学校不同，例如 appLoginHGD appLoginCHZU appLogin
        school_login_url = conf.get('Yun',"school_login_url", fallback='').strip()
        if not school_login_url:
            school_login_url = 'appLogin'
            print("config.ini 没有填 school_login_url，默认使用 appLogin（合工大是 appLoginHGD）")
        url = schoolHost + '/login/' + school_login_url

        if username != conf.get('Login', 'username'):
            conf.set('Login', 'username', username)
            _write_conf(conf, path)
        if password != conf.get('Login', 'password'):
            conf.set('Login', 'password', password)
            _write_conf(conf, path)
        #如果部分配置为空则随机生成
        if iniDeviceId != '':
            DeviceId = iniDeviceId
        else:
            DeviceId = str(random.randint(1000000000000000, 9999999999999999))
            conf.set('User', 'device_id', DeviceId)
            _write_conf(conf, path)
        if iniuuid != '':
            uuid = iniuuid
        else:
            uuid = DeviceId

        if iniDeviceName != '':
            DeviceName = iniDeviceName
        else:
            print('DeviceName为空 请输入希望使用的设备名\n留空则使用默认名')
            DeviceName = input() or 'Xiaomi'

        if iniSysedition != '':
            sys_edition = iniSysedition
        else:
            print('Sys_edition为空 请输入希望使用的设备名\n留空则使用14')
            sys_edition = input() or '14'

        # 固定信封登录要求 cipherkey 能解码成 16 字节 SM4 密钥
        default_key = conf.get('Yun', 'cipherkey', fallback='').strip()
        CipherKeyEncrypted = conf.get('Yun', 'cipherKeyEncrypted', fallback='').strip()
        try:
            sm4_key = b64decode(default_key)
        except Exception as exc:
            print("config.ini 里的 cipherkey 不是合法的 Base64：" + str(exc))
            return None
        if len(sm4_key) != 16:
            print("config.ini 里的 cipherkey 解码后应为 16 字节（当前 " + str(len(sm4_key)) + " 字节）。")
            print("请用 python genSM4Key.py 生成新密钥，并同步更新 cipherkey 和 cipherkeyencrypted。")
            return None
        if not CipherKeyEncrypted:
            print("config.ini 里的 cipherkeyencrypted 为空，cipherkey 与 cipherkeyencrypted 必须成对填写。")
            return None

        #md5签名结果用hex
        encryptData = '''{"password":"'''+password+'''","schoolId":"'''+schoolid+'''","userName":"'''+username+'''","type":"1"}'''
        #签名结果
        sign_data='platform=android&utc={}&uuid={}&appsecret={}'.format(utc,uuid,md5key)
        sign=md5_encryption(sign_data)
        content = encrypt_sm4(encryptData, sm4_key, isBytes=False)
        # content=content[:-24]
        headers = {
            "token": "",
            "isApp": "app",
            "deviceId": uuid,
            "deviceName": DeviceName,
            "version": appedition,
            "platform": platform,
            "uuid": uuid,
            "utc": str(utc),
            "sign": sign,
            "Content-Type": "application/json; charset=utf-8",
            "Accept-Encoding": "gzip",
            "User-Agent": "okhttp/3.12.0"
        }
        # 请求体内容
        data = {
            "cipherKey": CipherKeyEncrypted,
            "content": content
        }
        # 发送POST请求
        try:
            response = requests.post(url, headers=headers, json=data, timeout=(8, 20))
        except Exception as exc:
            print("登录请求发送失败：" + type(exc).__name__ + ": " + str(exc))
            print("请确认 " + schoolHost + " 能访问，并关掉 VPN/抓包代理后重试。")
            return None
        # 打印响应内容
        result=response.text

        if response.status_code != 200:
            print("登录请求返回 HTTP " + str(response.status_code) + "：" + result[:300])
            return None

        try:
            if "{" in result : # 有的学校会直接返回未加密内容 如果是JSON（用最粗暴的方式判断）
                DecryptedData = response.json()
            else :
                DecryptedData = json.loads(decrypt_sm4(result, sm4_key).decode())
        except Exception as exc:
            # 注意：以前这里是 except 不住的 IndexError（响应为空时 gmssl 直接崩），现在统一给可读提示
            print("登录响应解析失败：" + type(exc).__name__ + ": " + str(exc))
            print("原始响应：" + repr(result[:300]))
            print("请检查 school_login_url、app_edition，以及 cipherkey/cipherkeyencrypted 是否和学校匹配。")
            return None

        if not isinstance(DecryptedData, dict):
            print("登录响应格式异常：" + str(DecryptedData)[:300])
            return None
        # 判断是否返回错误信息并停止（code 兼容 int 200 和字符串 "200"）
        code = DecryptedData.get('code', 200)
        token = (DecryptedData.get('data') or {}).get('token')
        if str(code) != '200' :
            print("登录失败：" + str(DecryptedData.get('msg') or DecryptedData))
            return None

        if not token:
            print("登录响应里没有 token：" + str(DecryptedData)[:300])
            return None

        # 成功登录时 返回信息
        print("登录成功，本次登录尝试获得的token为：" + token + "  本次生成的uuid为：" + uuid)
        print("!请注意! 使用脚本登录后会导致手机客户端登录失效\n请尽量减少手机登录次数，避免被识别为多设备登录代跑")
        return token,DeviceId,DeviceName,uuid,sys_edition

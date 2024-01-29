#!/usr/bin/python3
# coding=utf-8

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import time
from urllib import parse

import requests
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from seleniumrequests import Chrome


class HuaWeiLocationClient(object):
    def __init__(self, phone, pwd):
        self._username = phone
        self._password = pwd
        self._driver = None
        self._token = None
        self._is_login = False
        self._device_info = {}
        self.huawei_host = 'https://cloud.huawei.com'
        self.token_list = {}
        self.session = requests.session()

    def post(self, path, data, headers={}):
        r = self.session.post(self.huawei_host + path, data=data, cookies=self._token, headers=headers)
        # print(f'{self._username}, path:{path}, data:{data}, cookies:{self._token}')
        response = r.json()
        # print(f'{self._username}, path:{path}, response: {response}')
        return response

    def get(self, path):
        # print(f'{self._username}, path:{path}, cookies:{self._token}')
        r = self.session.get(self.huawei_host + path, cookies=self._token)
        response = r.json()
        # print(f"{self._username}, response:{response}")
        return response

    def get_element(self, driver, find):
        return WebDriverWait(driver, 10, 0.2).until(EC.visibility_of_element_located(find))

    def start_driver(self, num=0):
        if num > 3:
            raise TypeError('重试3次还未加载')
        try:
            chrome_options = Options()
            chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
            chrome_options.add_argument('ignore-certificate-errors')
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--blink-settings=imagesEnabled=true')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--proxy-excludeSwitcher=enable-automation')
            # print(f'启动driver({self._username})')
            if self._driver is None:
                self._driver = Chrome(options=chrome_options)
            try:
                # print(f'开始登录({self._username})华为云')
                self._driver.get(self.huawei_host)
                self._driver.save_screenshot('/home/pi/1.jpg')
                self._driver.switch_to.frame(1)
                self.get_element(self._driver, (By.CSS_SELECTOR, ".userAccount")).send_keys(self._username)
                self.get_element(self._driver, (By.CSS_SELECTOR, ".hwid-input-pwd")).send_keys(self._password)
                elem = self.get_element(self._driver, (By.CSS_SELECTOR, ".hwid-btn"))
                self._driver.execute_script("arguments[0].click()", elem)
                self.get_element(self._driver, (By.CSS_SELECTOR, ".featuresText"))
                csrfToken = self._driver.get_cookie('CSRFToken')
                if csrfToken is not None:
                    self.csrfToken = ['value']
                self.token_list[self._username] = {'token': self._driver.get_cookie('token')['value'],
                                                   'loginID': self._driver.get_cookie('loginID')['value']}
            except Exception:
                csrfToken = self._driver.get_cookie('CSRFToken')
                if csrfToken is not None:
                    self.csrfToken = ['value']
                if self._driver.get_cookie('token')['value'] is not None:
                    self.token_list[self._username] = {'token': self._driver.get_cookie('token')['value'],
                                                       'loginID': self._driver.get_cookie('loginID')['value']}

            # self._driver.delete_all_cookies()
        except Exception as ex:
            print_msg(self._username, "start_driver failed: %s" % ex)
            self.start_driver(num + 1)
        self._is_login = False
        self._token = self.token_list[self._username]
        print_msg(self._username, "start_driver success")

    def update_device_info(self):
        response = self.post('/findDevice/getMobileDeviceList', data={"traceId": "01100_02_1658381855_85554532"})
        for i in response.get('deviceList', []):
            if i.get('deviceCategory') != 'phone':
                continue
            if i.get('deviceType') != 9:
                continue
            self._device_info[i['deviceId']] = i
        print_msg(self._username, "update_device_info success")

    def login(self):
        self.start_driver()
        self._is_login = True

        return self.update_device_info()

    def find(self, imei):
        device_info = self._device_info[imei]
        device_type = device_info['deviceType']
        # 更新位置
        data = {
            "cptList": "",
            "deviceId": imei,
            "deviceType": device_type,
            "perDeviceType": device_info["perDeviceType"],
            "traceId": f"01001_02_1659590663_75983514_{device_info['appVersion']}_{device_info['romVersion']}",
        }
        response = self.post('/findDevice/locate', data=data)
        if response['info'] != 'Success.':
            print_msg(self._username, 'locate device failed')
            return

        # 查询位置
        data = {
            'deviceId': imei,
            'deviceType': device_type
        }
        if 'senderUserId' in device_info:
            data['senderUserId'] = device_info['senderUserId']
            data['relationType'] = device_info['relationType']
        response = self.post('/findDevice/queryLocateResult', data=data)

        if (response['exeResult'] != '-1') or (
                response.get('code') == '0' and response.get('info') == 'Success.' and response.get('locateInfo')):
            locateInfo = json.loads(response['locateInfo'])
            data = {
                'name': device_info["deviceAliasName"],
                "latitude": locateInfo['latitude'],
                "longitude": locateInfo['longitude'],
                'updateTime': int(time.time())
            }
            print_msg(self._username, "find device %s success" % imei)
            return data

    def location(self):
        for imei, value in self._device_info.items():
            r = self.find(imei)
            return r


class XiaoMiLocationClient(object):

    def __init__(self, username, password):
        self._headers = {}
        self._cookies = {}
        self._username = username
        self._password = password
        self._sign = None
        self.userId = None
        self._serviceLoginAuth2_json = {}
        self.session = requests.session()

    def _get_sign(self):
        url = 'https://account.xiaomi.com/pass/serviceLogin?sid%3Di.mi.com&sid=i.mi.com&_locale=zh_CN&_snsNone=true'
        pattern = re.compile(r'_sign=(.*?)&')

        r = self.session.get(url, headers=self._headers)
        self._cookies['pass_trace'] = r.history[0].headers.get('Set-Cookie').split(";")[0].split("=")[1]
        self._sign = parse.unquote(pattern.findall(r.history[0].headers.get('Location'))[0])
        print(self._username, '_get_sign success')
        return True

    def _serviceLoginAuth2(self):
        url = 'https://account.xiaomi.com/pass/serviceLoginAuth2'
        self._headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '*/*',
            'Origin': 'https://account.xiaomi.com',
            'Referer': 'https://account.xiaomi.com/pass/serviceLogin?sid%3Di.mi.com&sid=i.mi.com&_locale=zh_CN&_snsNone=true',
            'Cookie': 'pass_trace={};'.format(self._cookies['pass_trace'])
        }

        auth_post_data = {'_json': 'true',
                          '_sign': self._sign,
                          'callback': 'https://i.mi.com/sts',
                          'hash': hashlib.md5(self._password.encode('utf-8')).hexdigest().upper(),
                          'qs': '%3Fsid%253Di.mi.com%26sid%3Di.mi.com%26_locale%3Dzh_CN%26_snsNone%3Dtrue',
                          'serviceParam': '{"checkSafePhone":false}',
                          'sid': 'i.mi.com',
                          'user': self._username}
        try:
            r = self.session.post(url, headers=self._headers, data=auth_post_data, cookies=self._cookies)
            self._cookies['pwdToken'] = r.cookies.get('passToken')
            self._serviceLoginAuth2_json = json.loads((r.text)[11:])
            print(self._username, '_serviceLoginAuth2 success')
            return True
        except BaseException as e:
            print(self._username, '_serviceLoginAuth2 failed: %s' % e.args[0])
            return False

    def _login_miai(self):
        serviceToken = "nonce={}&{}".format(
            self._serviceLoginAuth2_json['nonce'], self._serviceLoginAuth2_json['ssecurity'])
        serviceToken_sha1 = hashlib.sha1(serviceToken.encode('utf-8')).digest()
        base64_serviceToken = base64.b64encode(serviceToken_sha1)
        loginmiai_header = {'User-Agent': 'MISoundBox/1.4.0,iosPassportSDK/iOS-3.2.7 iOS/11.2.5',
                            'Accept-Language': 'zh-cn', 'Connection': 'keep-alive'}
        url = self._serviceLoginAuth2_json['location'] + \
              "&clientSign=" + parse.quote(base64_serviceToken.decode())
        try:
            r = self.session.get(url, headers=loginmiai_header)
            if r.status_code == 200:
                self._Service_Token = r.cookies.get('serviceToken')
                self.userId = r.cookies.get('userId')
                print(self._username, '_login_miai success')
                return True
            else:
                print(self._username, '_login_miai failed')
                return False
        except BaseException as e:
            print(self._username, '_login_miai failed: %s' % e.args[0])
            return False

    def _get_device_info(self):
        url = 'https://i.mi.com/find/device/full/status?ts={}'.format(
            int(round(time.time() * 1000)))
        get_device_list_header = {'Cookie': 'userId={};serviceToken={}'.format(
            self.userId, self._Service_Token)}
        try:
            r = self.session.get(url, headers=get_device_list_header)
            if r.status_code == 200:
                data = json.loads(r.text)['data']['devices']
                self._device_info = data
                print(self._username, '_get_device_info success')
            else:
                print(self._username, '_get_device_info failed')
        except Exception as ex:
            print(self._username, '_get_device_info failed: %s' % ex)

    def login(self):
        self._get_sign()
        self._serviceLoginAuth2()
        self._login_miai()
        self._get_device_info()
        self._send_find_device_command()
        time.sleep(5)

    def _send_find_device_command(self):
        for vin in self._device_info:
            imei = vin["imei"]
            url = 'https://i.mi.com/find/device/{}/location'.format(imei)
            _send_find_device_command_header = {
                'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}
            data = {'userId': self.userId, 'imei': imei,
                    'auto': 'false', 'channel': 'web', 'serviceToken': self._Service_Token}
            try:
                r = self.session.post(url, headers=_send_find_device_command_header, data=data)
                if r.status_code == 200:
                    print(self._username, '_send_find_device_command success')
                else:
                    print(self._username, '_send_find_device_command failed')
            except Exception as ex:
                print(self._username, "send find device command failed: %s" % ex)

    def location(self):
        for info in self._device_info:
            if info['deviceType'] != 'phone':
                continue
            url = 'https://i.mi.com/find/device/status?ts={}&fid={}'.format(
                int(round(time.time() * 1000)), info["imei"])
            _send_find_device_command_header = {
                'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}

            r = self.session.get(url, headers=_send_find_device_command_header)
            if r.status_code == 200:
                result = json.loads(r.text)
                if "receipt" in result.get('data', {}).get('location', {}):
                    receipt = result['data']['location']['receipt']
                    for gps in receipt['gpsInfoTransformed']:
                        if gps['coordinateType'] != 'baidu':
                            continue
                        device_info = {"latitude": gps['latitude'],
                                       "longitude": gps['longitude'],
                                       "name": info['model'],
                                       "updateTime": int(str(receipt['infoTime'])[:-3])}
                        return device_info


def print_msg(phone, msg):
    timestamps = str(datetime.datetime.now())
    print('%s %s %s' % (timestamps[:19], phone, msg))


def record_location(cfg, data):
    for username, d in data.items():
        if d['type'] == 'xiaomi':
            data_path = '%s/xiaomi/%s' % (cfg.directory, username)
            with open(data_path, 'w') as fl:
                fl.write(json.dumps(d))
        elif d['type'] == 'huawei':
            data_path = '%s/huawei/%s' % (cfg.directory, username)
            with open(data_path, 'w') as fl:
                fl.write(json.dumps(d))
        elif d['type'] == 'realme':
            data_path = '%s/realme/%s' % (cfg.directory, username)
            with open(data_path, 'w') as fl:
                fl.write(json.dumps(d))
        print_msg(username, 'write data: %s' % json.dumps(d))


def get_location(cfg):
    locations = {}
    for phone in cfg.xiaomi_phone:
        username, pwd = phone.split(',')
        # try:
        lc = XiaoMiLocationClient(username, pwd)
        lc.login()
        location = lc.location()
        if not location:
            continue
        locations[username] = {
            'location': location,
            'type': 'xiaomi',
            'datetime': str(datetime.datetime.fromtimestamp(location['updateTime']))
        }
        # except Exception as ex:
        #     print_msg(username, ex)

    for phone in cfg.huawei_phone:
        username, pwd = phone.split(',')
        # try:
        lc = HuaWeiLocationClient(username, pwd)
        lc.login()
        location = lc.location()
        if not location:
            continue
        locations[username] = {
            'location': location,
            'type': 'huawei',
            'datetime': str(datetime.datetime.fromtimestamp(location['updateTime']))
        }
        # except Exception as ex:
        #     print_msg(username, ex)

    record_location(cfg, locations)


def get_args():
    parser = argparse.ArgumentParser(
        description='Arguments for start phone location system')
    parser.add_argument('-d', '--directory',
                        default='/etc/location',
                        action='store',
                        help='set data directory')
    parser.add_argument('-xp', '--xiaomi-phone',
                        default=[],
                        action='append',
                        help='location xiaomi phones')
    parser.add_argument('-hp', '--huawei-phone',
                        default=[],
                        action='append',
                        help='location huawei phones')
    parser.add_argument('-rp', '--realme-phone',
                        default=[],
                        action='append',
                        help='location realme phones')
    args = parser.parse_args()
    return args


def init(cfg):
    if not os.path.exists(cfg.directory):
        os.mkdir(cfg.directory)

    if cfg.xiaomi_phone:
        xiaomi_dir = '%s/xiaomi' % cfg.directory
        if not os.path.exists(xiaomi_dir):
            os.mkdir(xiaomi_dir)

    if cfg.huawei_phone:
        huawei_dir = '%s/huawei' % cfg.directory
        if not os.path.exists(huawei_dir):
            os.mkdir(huawei_dir)

    if cfg.realme_phone:
        realme_dir = '%s/realme' % cfg.directory
        if not os.path.exists(realme_dir):
            os.mkdir(realme_dir)


if __name__ == '__main__':
    cfg = get_args()
    init(cfg)
    get_location(cfg)

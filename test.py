# -*- coding: utf-8 -*-

import requests
import json
import time
import hashlib
import base64
from urllib import parse
import logging
import re
import async_timeout
import asyncio as asy

from requests import Session


__version__ = '0.2.1'
_LOGGER = logging.getLogger(__name__)


class MiPhoneData(object):
    """获取相关的数据，存储在这个类中."""

    def __init__(self, user=None, password=None, coordinate_type=None):
        """初始化函数."""
        self.device_name = None
        self.device_imei = None
        self.device_phone = None
        self.device_lat = None
        self.device_lon = None
        self.device_accuracy = None
        self.device_power = None
        self.device_location_update_time = None
        self.deviceChoose = 0

        self.login_result = False

        self._user = user
        self._password = password
        self.coordinate_type = str(coordinate_type)
        self.Service_Token = None
        self.userId = None
        self._cookies = {}
        self._requests = requests.session()
        self._headers = {'Host': 'account.xiaomi.com',
                         'Connection': 'keep-alive',
                         'Upgrade-Insecure-Requests': '1',
                         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
                         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                         'Accept-Encoding': 'gzip, deflate, br',
                         'Accept-Language': 'zh-CN,zh;q=0.9'}

    @property
    def name(self):
        """设备名称."""
        return self.device_name

    @property
    def source_type(self):
        return "gps"

    @property
    def battery_level(self):
        return self.device_power

    @property
    def latitude(self):
        return self.device_lat

    @property
    def longitude(self):
        return self.device_lon

    @property
    def gps_accuracy(self):
        return self.device_accuracy

    @property
    def altitude(self):
        return 0

    @property
    def updatetime(self):
        """更新时间."""
        return self.device_location_update_time

    def _get_sign(self, session):
        url = 'https://account.xiaomi.com/fe/service/login?sid%3Di.mi.com=&sid=passport&qs=%253Fsid%25253Di.mi.com&callback=https%3A%2F%2Faccount.xiaomi.com&_sign=2%26V1_passport%26xZhYqdWygn%2FDO27ZiII2S8%2FV%2Bhc%3D&serviceParam=%7B%22checkSafePhone%22%3Afalse%2C%22checkSafeAddress%22%3Afalse%2C%22lsrp_score%22%3A0.0%7D&showActiveX=false&theme=&needTheme=false&bizDeviceType='
        pattern = re.compile(r'_sign":"(.*?)",')
        try:
            with async_timeout.timeout(15):
                r = requests.get(url, headers=self._headers)
            self._cookies['pass_trace'] = r.headers.getall('Set-Cookie')[2].split("=")[1].split(";")[0]
            self._sign = pattern.findall(r.text)[0]
            return True
        except BaseException as e:
            print(e.args[0])
            return False

    def _serviceLoginAuth2(self, session, captCode=None):
        url = 'https://account.xiaomi.com/pass/serviceLoginAuth2'
        self._headers['Content-Type'] = 'application/x-www-form-urlencoded'
        self._headers['Accept'] = '*/*'
        self._headers['Origin'] = 'https://account.xiaomi.com'
        self._headers[
            'Referer'] = 'https://account.xiaomi.com/pass/serviceLogin?sid%3Di.mi.com&sid=i.mi.com&_locale=zh_CN&_snsNone=true'
        self._headers['Cookie'] = 'pass_trace={};'.format(
            self._cookies['pass_trace'])

        auth_post_data = {'_json': 'true',
                          '_sign': self._sign,
                          'callback': 'https://i.mi.com/sts',
                          'hash': hashlib.md5(self._password.encode('utf-8')).hexdigest().upper(),
                          'qs': '%3Fsid%253Di.mi.com%26sid%3Di.mi.com%26_locale%3Dzh_CN%26_snsNone%3Dtrue',
                          'serviceParam': '{"checkSafePhone":false}',
                          'sid': 'i.mi.com',
                          'user': self._user}
        try:
            if captCode != None:
                url = 'https://account.xiaomi.com/pass/serviceLoginAuth2?_dc={}'.format(
                    int(round(time.time() * 1000)))
                auth_post_data['captCode'] = captCode
                self._headers['Cookie'] = self._headers['Cookie'] + \
                                          '; ick={}'.format(self._cookies['ick'])
            with async_timeout.timeout(15):
                r = session.post(url, headers=self._headers, data=auth_post_data, cookies=self._cookies)
            self._cookies['pwdToken'] = r.cookies.get('passToken').value
            self._serviceLoginAuth2_json = json.loads((r.text())[11:])
            return True
        except BaseException as e:
            print(e.args[0])
            return False

    def _login_miai(self, session):
        serviceToken = "nonce={}&{}".format(
            self._serviceLoginAuth2_json['nonce'], self._serviceLoginAuth2_json['ssecurity'])
        serviceToken_sha1 = hashlib.sha1(serviceToken.encode('utf-8')).digest()
        base64_serviceToken = base64.b64encode(serviceToken_sha1)
        loginmiai_header = {'User-Agent': 'MISoundBox/1.4.0,iosPassportSDK/iOS-3.2.7 iOS/11.2.5',
                            'Accept-Language': 'zh-cn', 'Connection': 'keep-alive'}
        url = self._serviceLoginAuth2_json['location'] + \
              "&clientSign=" + parse.quote(base64_serviceToken.decode())
        try:
            with async_timeout.timeout(15):
                r = session.get(url, headers=loginmiai_header)
            if r.status == 200:
                self._Service_Token = r.cookies.get('serviceToken').value
                self.userId = r.cookies.get('userId').value
                return True
            else:
                return False
        except BaseException as e:
            print(e.args[0])
            return False

    def _get_device_info(self, session):
        url = 'https://i.mi.com/find/device/full/status?ts={}'.format(
            int(round(time.time() * 1000)))
        get_device_list_header = {'Cookie': 'userId={};serviceToken={}'.format(
            self.userId, self._Service_Token)}
        try:
            with async_timeout.timeout(15):
                r = session.get(url, headers=get_device_list_header)
            if r.status == 200:
                self.device_name = json.loads(r.text())['data']['devices'][self.deviceChoose - 1]['model']
                self.device_imei = json.loads(r.text())['data']['devices'][self.deviceChoose - 1]['imei']
                self.device_phone = json.loads(r.text())['data']['devices'][self.deviceChoose - 1]['phone']

                return True
            else:
                return False
        except BaseException as e:
            print(e.args[0])
            return False

    def _send_find_device_command(self, session):
        url = 'https://i.mi.com/find/device/{}/location'.format(
            self.device_imei)
        _send_find_device_command_header = {
            'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}
        data = {'userId': self.userId, 'imei': self.device_imei,
                'auto': 'false', 'channel': 'web', 'serviceToken': self._Service_Token}
        try:
            with async_timeout.timeout(15):
                r = session.post(url, headers=_send_find_device_command_header, data=data)
            if r.status == 200:
                return True
            else:
                self.login_result = False
                return False
        except BaseException as e:
            print(e.args[0])
            self.login_result = False
            return False

    def _get_device_location(self, session):
        url = 'https://i.mi.com/find/device/status?ts={}&fid={}'.format(
            int(round(time.time() * 1000)), self.device_imei)
        _send_find_device_command_header = {
            'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}
        try:
            with async_timeout.timeout(15):
                r = session.get(url, headers=_send_find_device_command_header)
            if r.status == 200:
                location_info_json = {}
                if self.coordinate_type.find("baidu") != -1:
                    location_info_json = json.loads(r.text())['data']['location']['receipt']['gpsInfo']
                elif self.coordinate_type.find("google") != -1:
                    location_info_json = json.loads(r.text())['data']['location']['receipt']['gpsInfoExtra'][0]
                elif self.coordinate_type.find("original") != -1:
                    location_info_json = json.loads(r.text())['data']['location']['receipt']['gpsInfoExtra'][1]
                else:
                    print("coordinate_type {} not find in Mi Cloud!".format(self.coordinate_type))
                    self.login_result = False
                    return False

                self.device_lat = location_info_json['latitude']
                self.device_accuracy = int(location_info_json['accuracy'])
                self.device_lon = location_info_json['longitude']
                self.coordinate_type = location_info_json['coordinateType']

                self.device_power = json.loads(
                    r.text())['data']['location']['receipt']['powerLevel']
                self.device_phone = json.loads(
                    r.text())['data']['location']['receipt']['phone']
                timeArray = time.localtime(int(json.loads(
                    # r.text())['data']['location']['receipt']['infoTime']) / 1000 + 28800)
                    r.text())['data']['location']['receipt']['infoTime']) / 1000)
                self.device_location_update_time = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)

                return True
            else:
                self.login_result = False
                return False
        except BaseException as e:
            self.login_result = False
            print(e.args[0])
            return False

    def async_update(self, now):
        """从远程更新信息."""

        """
        # 异步模式的测试代码
        import time
        print("before time.sleep")
        time.sleep(40)
        print("after time.sleep and before asy.sleep")
        asy.sleep(40)
        print("after asy.sleep and before asy.sleep")
        asy.sleep(40)
        print("after asy.sleep")
        """

        # 通过HTTP访问，获取需要的信息
        # 此处使用了基于aiohttp库的async_get_clientsession
        try:
            session = Session()
            if self.login_result is True:
                tmp = self._send_find_device_command(session)
                if tmp is True:
                    # time.sleep(15)
                    asy.sleep(15)
                    tmp = self._get_device_location(session)
                    if tmp is True:
                        print("成功获取位置")
                        return
                    else:
                        print('get_device_location info Failed')

            tmp = self._get_sign(session)
            if not tmp:
                print("get_sign Failed")
            else:
                tmp = self._serviceLoginAuth2(session)
                if not tmp:
                    print('Request Login_url Failed')
                else:
                    if self._serviceLoginAuth2_json['code'] == 0:
                        # logon success,run self._login_miai()
                        tmp = self._login_miai(session)
                        if not tmp:
                            print('login Mi Cloud Failed')
                        else:
                            tmp = self._get_device_info(session)
                            if not tmp:
                                print('get_device info Failed')
                            else:
                                print("get_device info succeed")
                                self.login_result = True
                                tmp = self._send_find_device_command(session)
                                if tmp is True:
                                    #time.sleep(15)
                                    asy.sleep(15)
                                    tmp = self._get_device_location(session)
                                    if tmp is True:
                                        print("get_device_location info succeed")
                                    else:
                                        print('get_device_location info Failed')

        except Exception as ex:
            print("Error while accessing: something wrong %s" % ex)
            return

        print("success to fetch local info from Mi API")


phone = MiPhoneData(user='186xxxxxxxx', password='88888888')
phone.async_update(time.time())
for i in range(10000):
    print(phone.latitude, phone.longitude)
    time.sleep(5)
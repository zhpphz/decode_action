from requests import post, get
from time import sleep, time
from hashlib import md5 as md5Encode
from datetime import datetime, timedelta
from random import randint, uniform, choice
from sys import stdout, exit
from base64 import b64encode
from json import dumps
import threading
import pytz
import os
import urllib.request
import json
import sys
import random

"""\xe4\xb8\xbb\xe7\xb1\xbb"""
try:
    from Crypto.Cipher import AES, DES, DES3
except:
    print("\xe6\xa3\x80\xe6\xb5\x8b\xe5\x88\xb0\xe8\xbf\x98\xe6\x9c\xaa\xe5\xae\x89\xe8\xa3\x85 pycryptodome \xe8\xaf\xb7\xe6\x8c\x89\xe7\x85\xa7md\xe7\x9a\x84\xe6\x96\xb9\xe6\xb3\x95\xe5\xae\x89\xe8\xa3\x85")
    exit(0)
from binascii import b2a_hex, a2b_hex
from base64 import b64encode, b64decode


class Crypt:
    def __init__(self, crypt_type: str, key, iv=None, mode="ECB"):
        """

        :param crypt_type: \xe5\xaf\xb9\xe7\xa7\xb0\xe5\x8a\xa0\xe5\xaf\x86\xe7\xb1\xbb\xe5\x9e\x8b \xe6\x94\xaf\xe6\x8c\x81AES, DES, DES3
        :param key: \xe5\xaf\x86\xe9\x92\xa5 (aes\xe5\x8f\xaf\xe9\x80\x89 16/32(24\xe4\xbd\x8d\xe6\x9a\x82\xe4\xb8\x8d\xe6\x94\xaf\xe6\x8c\x81 \xe4\xbb\xa5\xe5\x90\x8e\xe9\x81\x87\xe5\x88\xb0\xe6\x9c\x89\xe9\x9c\x80\xe8\xa6\x81\xe5\x86\x8d\xe8\xa1\xa5)  des \xe5\x9b\xba\xe5\xae\x9a\xe4\xb8\xba8 des3 24(\xe6\x9a\x82\xe4\xb8\x8d\xe6\x94\xaf\xe6\x8c\x8116 16\xe5\xba\x94\xe8\xaf\xa5\xe4\xb9\x9f\xe4\xb8\x8d\xe4\xbc\x9a\xe5\x86\x8d\xe4\xbd\xbf\xe7\x94\xa8\xe4\xba\x86) \xe4\xb8\x80\xe8\x88\xac\xe9\x83\xbd\xe4\xb8\xba24 \xe5\x88\x86\xe4\xb8\xba8\xe9\x95\xbf\xe5\xba\xa6\xe7\x9a\x84\xe4\xb8\x89\xe7\xbb\x84 \xe8\xbf\x9b\xe8\xa1\x8c\xe4\xb8\x89\xe6\xac\xa1des\xe5\x8a\xa0\xe5\xaf\x86
        :param iv: \xe5\x81\x8f\xe7\xa7\xbb\xe9\x87\x8f
        :param mode: \xe6\xa8\xa1\xe5\xbc\x8f CBC/ECB
        """
        if crypt_type.upper() not in ["AES", "DES", "DES3"]:
            raise Exception("\xe5\x8a\xa0\xe5\xaf\x86\xe7\xb1\xbb\xe5\x9e\x8b\xe9\x94\x99\xe8\xaf\xaf, \xe8\xaf\xb7\xe9\x87\x8d\xe6\x96\xb0\xe9\x80\x89\xe6\x8b\xa9 AES/DES/DES3")
        self.crypt_type = AES if crypt_type.upper() == "AES" else DES if crypt_type.upper() == "DES" else DES3
        self.block_size = self.crypt_type.block_size
        if self.crypt_type == DES:
            self.key_size = self.crypt_type.key_size
        elif self.crypt_type == DES3:
            self.key_size = self.crypt_type.key_size[1]
        else:
            if len(key) <= 16:
                self.key_size = self.crypt_type.key_size[0]
            elif len(key) > 24:
                self.key_size = self.crypt_type.key_size[2]
            else:
                self.key_size = self.crypt_type.key_size[1]
                print("\xe5\xbd\x93\xe5\x89\x8daes\xe5\xaf\x86\xe9\x92\xa5\xe7\x9a\x84\xe9\x95\xbf\xe5\xba\xa6\xe5\x8f\xaa\xe5\xa1\xab\xe5\x85\x85\xe5\x88\xb024 \xe8\x8b\xa5\xe9\x9c\x80\xe8\xa6\x8132 \xe8\xaf\xb7\xe6\x89\x8b\xe5\x8a\xa8\xe7\x94\xa8 chr(0) \xe5\xa1\xab\xe5\x85\x85")
        if len(key) > self.key_size:
            key = key[:self.key_size]
        else:
            if len(key) % self.key_size != 0:
                key = key + (self.key_size - len(key) % self.key_size) * chr(0)
        self.key = key.encode("utf-8")
        if mode == "ECB":
            self.mode = self.crypt_type.MODE_ECB
        elif mode == "CBC":
            self.mode = self.crypt_type.MODE_CBC
        else:
            raise Exception("\xe6\x82\xa8\xe9\x80\x89\xe6\x8b\xa9\xe7\x9a\x84\xe5\x8a\xa0\xe5\xaf\x86\xe6\xa8\xa1\xe5\xbc\x8f\xe9\x94\x99\xe8\xaf\xaf")
        if iv is None:
            self.cipher = self.crypt_type.new(self.key, self.mode)
        else:
            if isinstance(iv, str):
                iv = iv[:self.block_size]
                self.cipher = self.crypt_type.new(self.key, self.mode, iv.encode("utf-8"))
            elif isinstance(iv, bytes):
                iv = iv[:self.block_size]
                self.cipher = self.crypt_type.new(self.key, self.mode, iv)
            else:
                raise Exception("\xe5\x81\x8f\xe7\xa7\xbb\xe9\x87\x8f\xe4\xb8\x8d\xe4\xb8\xba\xe5\xad\x97\xe7\xac\xa6\xe4\xb8\xb2")

    def encrypt(self, data, padding="pkcs7", b64=False):
        """

        :param data: \xe7\x9b\xae\xe5\x89\x8d\xe6\x9a\x82\xe4\xb8\x8d\xe6\x94\xaf\xe6\x8c\x81bytes \xe5\x8f\xaa\xe6\x94\xaf\xe6\x8c\x81string \xe6\x9c\x89\xe9\x9c\x80\xe6\xb1\x82\xe5\x86\x8d\xe8\xa1\xa5
        :param padding: pkcs7/pkck5 zero
        :param b64: \xe8\x8b\xa5\xe9\x9c\x80\xe8\xa6\x81\xe5\xbe\x97\xe5\x88\xb0base64\xe7\x9a\x84\xe5\xaf\x86\xe6\x96\x87 \xe5\x88\x99\xe4\xb8\xbaTrue
        :return:
        """
        pkcs7_padding = lambda s: s + (self.block_size - len(s.encode()) % self.block_size) * chr(
            self.block_size - len(s.encode()) % self.block_size)
        zero_padding = lambda s: s + (self.block_size - len(s) % self.block_size) * chr(0)
        pad = pkcs7_padding if padding == "pkcs7" else zero_padding
        data = self.cipher.encrypt(pad(data).encode("utf8"))
        encrypt_data = b64encode(data) if b64 else b2a_hex(data)  # \xe8\xbe\x93\xe5\x87\xbahex\xe6\x88\x96\xe8\x80\x85base64
        return encrypt_data.decode('utf8')


class China_Unicom:
    def __init__(self, phone_num, run_ua):
        self.phone_num = phone_num
        default_ua = f"Mozilla/5.0 (iPhone; CPU iPhone OS {randint(15, 17)}_{randint(0, 6)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 unicom{{version:iphone_c@11.0{randint(0, 7)}00}}"
        if run_ua is None or run_ua == "":
            run_ua = default_ua
        # print("\xe4\xbd\xbf\xe7\x94\xa8\xe7\x9a\x84UA\xef\xbc\x9a"+run_ua)

        self.headers = {
            "Host": "10010.woread.com.cn",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh-Hans;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json;charset=utf-8",
            'accesstoken': "ODZERTZCMjA1NTg1MTFFNDNFMThDRDYw",
            "Origin": "https://10010.woread.com.cn",
            "User-Agent": run_ua,
            "Connection": "keep-alive",
            "Referer": "https://10010.woread.com.cn/ng_woread/",
        }
        self.fail_num = 0

    def timestamp(self):
        return round(time() * 1000)

    def print_now(self, content):
        print(content)
        stdout.flush()

    def md5(self, str):
        m = md5Encode(str.encode(encoding='utf-8'))
        return m.hexdigest()

    def req(self, url, crypt_text, retry_num=2):
        while retry_num > 0:
            body = {"sign": b64encode(
                Crypt(crypt_type="AES", key="woreadst^&*12345", iv="16-Bytes--String", mode="CBC").encrypt(
                    crypt_text).encode()).decode()}
            self.headers["Content-Length"] = str(len(dumps(body).replace(" ", "")))
            try:
                res = post(url, headers=self.headers, json=body)
                data = res.json()
                return data
            except Exception as e:
                retry_num -= 1
                return self.req(url, crypt_text, retry_num)

    def referer_login(self):
        date = datetime.datetime.today().strftime("%Y%m%d%H%M%S")
        timestamp = self.timestamp()
        url = f"https://10010.woread.com.cn/ng_woread_service/rest/app/auth/10000002/{timestamp}/{self.md5(f'100000027k1HcDL8RKvc{timestamp}')}"
        crypt_text = f'{{"timestamp":"{date}"}}'
        body = {
            "sign": b64encode(Crypt(crypt_type="AES", key="1234567890abcdef").encrypt(crypt_text).encode()).decode()}
        self.headers["Content-Length"] = str(len(str(body)) - 1)
        data = post(url, headers=self.headers, json=body).json()
        if data["code"] == "0000":
            self.headers["accesstoken"] = data["data"]["accesstoken"]

        else:
            self.print_now(f"\xe8\xae\xbe\xe5\xa4\x87\xe7\x99\xbb\xe5\xbd\x95\xe5\xa4\xb1\xe8\xb4\xa5,\xe6\x97\xa5\xe5\xbf\x97\xe4\xb8\xba{data}")
            exit(0)

    def get_userinfo(self):
        date = datetime.today().strftime("%Y%m%d%H%M%S")
        url = "https://10010.woread.com.cn/ng_woread_service/rest/account/login"
        crypt_text = f'{{"phone":"{self.phone_num}","timestamp":"{date}"}}'
        data = self.req(url, crypt_text)
        if data["code"] == "0000":
            self.userinfo = data["data"]
            print(f"\xe7\x99\xbb\xe5\xbd\x95\xe8\xb4\xa6\xe5\x8f\xb7{data['data']['phone']}\xe6\x88\x90\xe5\x8a\x9f")
        else:
            self.print_now(f"\xe6\x89\x8b\xe6\x9c\xba\xe5\x8f\xb7\xe7\x99\xbb\xe5\xbd\x95\xe5\xa4\xb1\xe8\xb4\xa5, \xe6\x97\xa5\xe5\xbf\x97\xe4\xb8\xba{data}")
            exit(0)

    def lqrenwu(self):
        url = "https://10010.woread.com.cn/ng_woread_service/rest/activity423/receiveActiveTask"
        date = datetime.today().__format__("%Y%m%d%H%M%S")
        crypt_text = f'{{"activeId":{active_id},"taskId":{_240task_id},"timestamp":"{date}","token":"{self.userinfo["token"]}","userId":"{self.userinfo["userid"]}","userIndex":{self.userinfo["userindex"]},"userAccount":"{self.userinfo["phone"]}","verifyCode":"{self.userinfo["verifycode"]}"}}'
        data = self.req(url, crypt_text)
        try:
            if 'innercode' in data and (data['innercode']) == "7777":
                self.get_userinfo()
            if 'data' in data:
                print(data['data'])
            else:
                print(data['message'])
        except Exception as e:
            print(f"\xe8\xaf\xb7\xe6\xb1\x82\xe5\xa4\xb1\xe8\xb4\xa5")

    def lqre(self):
        url = "https://10010.woread.com.cn/ng_woread_service/rest/activity423/receiveActiveTask"
        date = datetime.today().__format__("%Y%m%d%H%M%S")
        crypt_text = f'{{"activeId":{active_id},"taskId":{_120task_id},"timestamp":"{date}","token":"{self.userinfo["token"]}","userId":"{self.userinfo["userid"]}","userIndex":{self.userinfo["userindex"]},"userAccount":"{self.userinfo["phone"]}","verifyCode":"{self.userinfo["verifycode"]}"}}'
        data = self.req(url, crypt_text)
        try:
            if 'innercode' in data and (data['innercode']) == "7777":
                self.get_userinfo()
            if 'data' in data:
                print(data['data'])
            else:
                print(data['message'])
        except Exception as e:
            print(f"\xe8\xaf\xb7\xe6\xb1\x82\xe5\xa4\xb1\xe8\xb4\xa5")

    def yuedu(self):
        url = "https://10010.woread.com.cn/ng_woread_service/rest/history/addReadTime"
        while True:
            timestamp = self.timestamp()
            date = datetime.today().strftime("%Y%m%d%H%M%S")
            crypt_text = f'{{"timestamp":"{date}","token":"{self.userinfo["token"]}","userId":"{self.userinfo["userid"]}","readTime":2,"cntindex":"409672","cntIndex":"409672","cnttype":"1","cntType":1,"cardid":"11891","catid":"118411","pageIndex":"10683","chapterseno":1,"channelid":"","chapterid":"-1","readtype":1,"isend":"0","signtimestamp":{timestamp}}}'
            data = self.req(url, crypt_text)
            if 'innercode' in data and data['innercode'] == "7777":
                self.get_userinfo()
            if 'data' in data:
                num_times_two = data['data']['num'] * 2
                print(f"{self.phone_num}\xe5\xb7\xb2\xe7\xbb\x8f\xe5\x88\xb7\xe4\xba\x86{num_times_two}\xe5\x88\x86\xe9\x92\x9f")
                if num_times_two >= 240:
                    self.cxrenwu()
                    break
                random_time = random.randint(123, 150)
                sleep(random_time)
            else:
                print("\xe5\x88\xb7\xe9\x98\x85\xe8\xaf\xbb\xe5\xa4\xb1\xe8\xb4\xa5\xef\xbc\x9a\xe7\x9f\xad\xe6\x97\xb6\xe9\x97\xb4\xe5\x86\x85\xe8\xaf\xb7\xe6\xb1\x82\xe8\xbf\x87\xe5\xa4\x9a\xe6\x88\x96\xe8\x80\x85\xe7\xbd\x91\xe7\xbb\x9c\xe9\x97\xae\xe9\xa2\x98")
                random_time = random.randint(123, 150)
                sleep(random_time)

    def cxrenwu(self):
        url = "https://10010.woread.com.cn/ng_woread_service/rest/activity423/queryCurTaskStatus"
        timestamp = self.timestamp()
        date = datetime.today().__format__("%Y%m%d%H%M%S")
        crypt_text = f'{{"activeIndex":{active_id},"timestamp":"{date}","token":"{self.userinfo["token"]}","userId":"{self.userinfo["userid"]}","userIndex":{self.userinfo["userindex"]},"userAccount":"{self.userinfo["phone"]}","verifyCode":"{self.userinfo["verifycode"]}"}}'
        data = self.req(url, crypt_text)
        try:
            ids = [item['id'] for item in data['data'] if 'id' in item]
            number_of_ids = len(ids)
            for id_value in ids:
                self.liqujl(id_value)
            self.cjrenwu()
            sleep(2)
            self.cxye()
        except Exception as e:
            self.cjrenwu()
            sleep(2)
            self.cxye()

    def liqujl(self, id_value):
        url = "https://10010.woread.com.cn/ng_woread_service/rest/activity423/completeActiveTask"
        timestamp = self.timestamp()
        date = datetime.today().__format__("%Y%m%d%H%M%S")
        crypt_text = f'{{"taskId":{id_value},"timestamp":"{date}","token":"{self.userinfo["token"]}","userId":"{self.userinfo["userid"]}","userIndex":{self.userinfo["userindex"]},"userAccount":"{self.userinfo["phone"]}","verifyCode":"{self.userinfo["verifycode"]}"}}'
        data = self.req(url, crypt_text)
        try:
            if (data['code']) == "0000":
                groupName = data['data']['exchangeResult']['materialGroupInfo']['groupName']
                print(f"{self.phone_num}\xe9\xa2\x86\xe5\x8f\x96{groupName}\xe6\x88\x90\xe5\x8a\x9f")
        except Exception as e:
            print(f"\xe8\xaf\xb7\xe6\xb1\x82\xe5\xa4\xb1\xe8\xb4\xa5")

    def cjrenwu(self):
        url = "https://10010.woread.com.cn/ng_woread_service/rest/activity423/drawReadActivePrize"
        timestamp = self.timestamp()
        date = datetime.today().__format__("%Y%m%d%H%M%S")
        crypt_text = f'{{"activeIndex":{active_id},"timestamp":"{date}","token":"{self.userinfo["token"]}","userId":"{self.userinfo["userid"]}","userIndex":{self.userinfo["userindex"]},"userAccount":"{self.userinfo["phone"]}","verifyCode":"{self.userinfo["verifycode"]}"}}'
        data = self.req(url, crypt_text)
        try:
            if (data['code']) == "0000":
                cjhd = data['data']['prizedesc']
                print(f"{self.phone_num}\xe6\x8a\xbd\xe5\xa5\x96\xe8\x8e\xb7\xe5\xbe\x97{cjhd}")
        except Exception as e:
            print(f"\xe8\xaf\xb7\xe6\xb1\x82\xe5\xa4\xb1\xe8\xb4\xa5")

    def cxye(self):
        url = "https://10010.woread.com.cn/ng_woread_service/rest/phone/vouchers/queryTicketAccount"
        timestamp = self.timestamp()
        date = datetime.today().__format__("%Y%m%d%H%M%S")
        crypt_text = f'{{"timestamp":"{date}","token":"{self.userinfo["token"]}","userId":"{self.userinfo["userid"]}","userIndex":{self.userinfo["userindex"]},"userAccount":"{self.userinfo["phone"]}","verifyCode":"{self.userinfo["verifycode"]}"}}'
        data = self.req(url, crypt_text)
        if (data['code']) == "0000":
            hbcx = data['data']['usableNum'] / 100
            print(f"{self.phone_num}\xe9\x98\x85\xe8\xaf\xbb\xe5\x8c\xba\xe8\xaf\x9d\xe8\xb4\xb9\xe7\xba\xa2\xe5\x8c\x85\xe4\xbd\x99\xe9\xa2\x9d{hbcx}\xe5\x85\x83")

    def main(self):
        # self.referer_login()
        self.get_userinfo()
        current_hour = datetime.now().hour
        if current_hour == 23:
            url = "https://f.m.suning.com/api/ct.do"
            try:
                with urllib.request.urlopen(url) as response:
                    datal = response.read().decode('utf-8')
                    json_data = json.loads(datal)
                    wlsjc_str = json_data.get('currentTime')  # \xe8\x8e\xb7\xe5\x8f\x96t\xe7\x9a\x84\xe5\xad\x97\xe7\xac\xa6\xe4\xb8\xb2\xe5\x80\xbc
                    wlsjc = int(wlsjc_str)
            except urllib.error.URLError as e:
                print(f"GET\xe8\xaf\xb7\xe6\xb1\x82\xe5\xa4\xb1\xe8\xb4\xa5")
            now = datetime.fromtimestamp(wlsjc / 1000)
            next_day = now + timedelta(days=1)
            next_day = next_day.replace(hour=0, minute=0, second=0, microsecond=0)
            delta = next_day - now
            seconds = delta.total_seconds()
            if wlsjc / 1000 > ymsjc:
                print(gongg)
                exit()
            print(f"\xe8\xb7\x9d\xe7\xa6\xbb\xe4\xb8\x8b\xe4\xb8\x80\xe5\xa4\xa9\xe9\x9b\xb6\xe7\x82\xb9\xe8\xbf\x98\xe6\x9c\x89 {seconds:.0f} \xe7\xa7\x92")
            if 'zdf' in locals() and zdf is not None:
                zdyz = int(zdy)
            else:
                zdyz = 3
            sleep(seconds - zdyz)
            threads = []
            for _ in range(dys):
                thread = threading.Thread(target=self.lqrenwu)
                threads.append(thread)
                thread.start()
                sleep(0.1)
            for _ in range(2):
                thread_lqre = threading.Thread(target=self.lqre)
                threads.append(thread_lqre)
                thread_lqre.start()
                sleep(0.1)
            for thread in threads:
                thread.join()
        else:
            self.yuedu()


def start(phone, run_ua, ):
    if phone == "":
        exit(0)
    China_Unicom(phone, run_ua).main()


if __name__ == "__main__":
    """\xe8\xaf\xbb\xe5\x8f\x96\xe7\x8e\xaf\xe5\xa2\x83\xe5\x8f\x98\xe9\x87\x8f"""
    url = "https://gitee.com/kele2233/genxin/raw/master/ltyddh.json"
    try:
        with urllib.request.urlopen(url) as response:
            data = response.read()
            json_data = json.loads(data)
            ging = json_data.get('gin')  # \xe8\x8e\xb7\xe5\x8f\x96 gongg \xe7\x9a\x84\xe5\x80\xbc
            fwbbh = json_data.get('fwbbh')  # \xe8\x8e\xb7\xe5\x8f\x96 gongg \xe7\x9a\x84\xe5\x80\xbc
            gonggg = json_data.get('gongg')  # \xe8\x8e\xb7\xe5\x8f\x96 gongg \xe7\x9a\x84\xe5\x80\xbc
            active_id = json_data.get('activeId')
            _240task_id = json_data.get('240taskId')
            _120task_id = json_data.get('120taskId')
            ymsjc = json_data.get('ydsjc')
            gongg = json_data.get('gong')
            dys = json_data.get('dys')
            bbh = 1.1
            if bbh >= fwbbh:
                print(f"\xe5\x85\xac\xe5\x91\x8a: {ging}\
\xe5\xbd\x93\xe5\x89\x8d\xe7\x89\x88\xe6\x9c\xac\xe5\x8f\xb7{bbh}\xe6\x9c\x80\xe6\x96\xb0\xe7\x89\x88\xe5\x8f\xb7{fwbbh}")  # \xe5\x9c\xa8\xe4\xb8\xbb\xe7\xba\xbf\xe7\xa8\x8b\xe4\xb8\xad\xe6\x89\x93\xe5\x8d\xb0 gongg \xe7\x9a\x84\xe5\x80\xbc
            else:
                print(f"{gonggg}\
\xe5\xbd\x93\xe5\x89\x8d\xe7\x89\x88\xe6\x9c\xac\xe5\x8f\xb7{bbh}\xe6\x9c\x80\xe6\x96\xb0\xe7\x89\x88\xe5\x8f\xb7{fwbbh}")
                exit(1)
    except urllib.error.URLError as e:
        exit(1)
    cklist = os.getenv("PHONE_NUM").split("&")[0]
    zdy = os.getenv("YDYC")
    threads = []  # \xe6\x9b\xb4\xe6\x94\xb9\xe5\x88\x97\xe8\xa1\xa8\xe5\x90\x8d\xe4\xb8\xba threads \xe4\xbb\xa5\xe6\x9b\xb4\xe6\xb8\x85\xe6\x99\xb0\xe5\x9c\xb0\xe8\xa1\xa8\xe8\xbe\xbe\xe5\x85\xb6\xe7\x94\xa8\xe9\x80\x94

    phone = cklist
    run_ua = None  # \xe5\xa6\x82\xe6\x9e\x9c\xe6\xb2\xa1\xe6\x9c\x89 UA\xef\xbc\x8c\xe5\x88\x99\xe8\xae\xbe\xe4\xb8\xba None
    print(f'\xe5\xbc\x80\xe5\xa7\x8b\xe6\x89\xa7\xe8\xa1\x8c\xe7\xac\xac{len(threads) + 1}\xe4\xb8\xaa\xe8\xb4\xa6\xe5\x8f\xb7\xef\xbc\x9a{phone}')
    p = threading.Thread(target=start, args=(phone, run_ua))
    threads.append(p)
    p.start()

    # \xe7\xad\x89\xe5\xbe\x85\xe6\x89\x80\xe6\x9c\x89\xe7\xba\xbf\xe7\xa8\x8b\xe5\xae\x8c\xe6\x88\x90
    for t in threads:
        t.join()



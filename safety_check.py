import functools
import json
import time

import requests
import yaml


def slow_down(func):
    """Sleep 1 second before calling the function"""
    @functools.wraps(func)
    def wrapper_slow_down(*args, **kwargs):
        time.sleep(1)
        return func(*args, **kwargs)
    return wrapper_slow_down

@slow_down

class VirusTotaler:
    def __init__(self, cfg):
        self.cfg = cfg



    def vt_get(self, url):

        apikey = self.cfg['virustotal']['apikey']

        vtendpt = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': apikey, 'resource': url}


        response = requests.get(vtendpt, params=params)
        response = response.json()

        if response['response_code'] == 0:
            pass
        print(response)
        print(response['positives'])


# vt_get('http://www.google23r432rf2.com')

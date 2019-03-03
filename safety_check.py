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
        apikey = self.cfg['virustotal']['apikey']

    def process_url(self, url):
        pass


    def vt_get(self, url):

        apikey = self.cfg['virustotal']['apikey']
        getendpt = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': apikey, 'resource': url}


        response = requests.get(getendpt, params=params)
        response = response.json()

        if response['response_code'] == -2:
            logger.info('[!] - Url {} not ready, sleeping'.format(url)
            sleep(5)
            return url_tocheck

        print(response)
        print(response['positives'])

    def vt_put(self, url):
        url_tocheck = self.
        

        putendptl = 'https://www.virustotal.com/vtapi/v2/url/scan'

        params = {'apikey': '<apikey>', 'url': url }

        response = requests.post(url, data=params)

        print(response.json())


# vt_get('http://www.google23r432rf2.com')


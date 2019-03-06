import functools
import json
import time
import urllib.parse as urlparse
import http.client as httplib

import requests
import yaml
import logs.logtweets as logtweets


logger = logtweets.configure_logger('default', './logs/safety_check.log')


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
        self.apikey = self.cfg['virustotal']['apikey']




    def process_url(self, url):
        parsed = urlparse.urlparse(url)
        h = httplib.HTTPConnection(parsed.netloc)
        resource = parsed.path
        if parsed.query != "":
            resource += "?" + parsed.query
        h.request('HEAD', resource )
        response = h.getresponse()
        if response.status/100 == 3 and response.getheader('Location'):
            url = unshorten_url(response.getheader('Location')) # changed to process chains of short urls
        else:
            url = url

        positives, reference = self.vt_get(url)

        return positives, reference
    def vt_get(self, url):

        getendpt = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': self.apikey, 'resource': url}


        response = requests.get(getendpt, params=params)
        if response.status_code == 204:
            logger.error('[!] - API Limit exceeded!!! Sleeping for 61 seconds...')
            time.sleep(61)
            self.vt_get(url)
        print(response)
        response = response.json()
        print(response)

        if response['response_code'] == -2:
            logger.info('[!] - Url {} not ready, sleeping'.format(url))
            time.sleep(10)
            self.vt_get(self, url)
        elif response['response_code'] == 0:
            logger.info('[-] url {} not found, submitting to scan'.format(url))
            self.vt_put(url)
        else:
            positives = response['positives']
            reference = response['permalink']
            return positives, reference

        print(response)
        if response['response_code'] == 1:
            print(response['positives'])

    def vt_put(self, url):
        print('starting put')
        
        putendpt = 'https://www.virustotal.com/vtapi/v2/url/scan'

        params = {'apikey': self.apikey, 'url': url }

        response = requests.post(putendpt, data=params)
        print(response.json())
        time.sleep(2)

        self.vt_get(url)



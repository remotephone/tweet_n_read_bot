import functools
import json
import os
import sqlite3
import time

import pandas as pd
import requests
import yaml
from twython import Twython

import logs.logtweets as logtweets
from safety_check import VirusTotaler


CURRENTDIR = os.path.dirname(__file__)
print(CURRENTDIR)
COUNT = 0


def handle_db():
    try:
        conn = sqlite3.connect("tweets.db")
        logger.info("[-] Opened DB")
        return conn
    except sqlite3.Error as e:
        logger.error("[!]" + e + ": Unable to open DB")
        raise SystemExit


# TODO: Clean up this logic

def put_tweets(cfg, query, conn):

# TODO: Add argparse for counts
    
    query = {'q': query,  
            'result_type': 'mixed',
            'count': 20,
            'lang': 'en',
            }


    # Create dictionary to search tweets and get them
    dict_ = {'user': [], 'date': [], 'text': [], 'favorite_count': [], 'url': [], 'scanned': [], 'positives': [], 'vt_link': []}
    python_tweets = Twython(cfg['twitter']['CONSUMER_KEY'], cfg['twitter']['CONSUMER_SECRET'])


    # loop to process tweets. your search returns a list per query
    # I only care about a few values, like name, create date, text, and urls
    # Twitter will extract URLs from tweets and expand them out
    logger.info('[-] {} tweets to process for {}'.format(len(python_tweets.search(**query)['statuses']), query['q']))
    for status in python_tweets.search(**query)['statuses']:
        if status['entities']['urls']:
            dict_['user'].append(status['user']['screen_name'])
            dict_['date'].append(status['created_at'])
            dict_['text'].append(status['text'])
            dict_['favorite_count'].append(status['favorite_count'])

            # Handle some tweet logic
            # Create a set so we don't have dupicates, go through URLs and add them to list
            # loop through, expand out twitter URLs, keep adding them to set 
            # keep iterating through set until all twitter urls are removed
            temp_list = set()
            if status['entities']['urls']:
                for url in status['entities']['urls']:
                    temp_list.add(url['expanded_url'])
            for url in temp_list:
                if 'twitter.com/i/web/status' in url:
                    status_id = url.split('/')[-1]
                    tweet = python_tweets.show_status(id=status_id)
                    for url in tweet['entities']['urls']:
                        if url['expanded_url']:
                            print(url)
                            url = url['expanded_url']
                            temp_list.add(url)
                else:
                    print(url)
                    temp_list.add(url)
                    for url in temp_list:
                        dict_['url'].append(url)
            else:
                dict_['url'].append('Null')
            dict_['scanned'].append('false')
            dict_['positives'].append(0)
            dict_['vt_link'].append('Null')

    # Create pandas dataframe. orient='index' allows me to handle empty fields, yuo also hae to transpose the dataframe
    df = pd.DataFrame.from_dict(dict_, orient='index',)  
    df = df.transpose()

    # now we sort them and want to make sure the sql database gets the full value of the column with the max width
    df.sort_values(by='date', inplace=True, ascending=False)
    pd.set_option('display.max_colwidth', -1)

    # write it to the DB, we don't necessarily need to return.
    # if_exists can be append or replace
    df.to_sql('tweets', conn, if_exists='replace', index=False)



def slow_down(func):
    """Sleep 1 second before calling the function"""
    @functools.wraps(func)
    def wrapper_slow_down(*args, **kwargs):
        logger.info('[-] Sleeper delaying next submissions')
        time.sleep(15)
        return func(*args, **kwargs)
    return wrapper_slow_down

@slow_down
def create_rss(cfg, url):
    vt = VirusTotaler(cfg)

    logger.info('[-] Safety checking {}'.format(url[0]))
    positives, reference = vt.process_url(url[0])
    return positives, reference

def main():

    
    # Find me and load config from subdirectory
    print(CURRENTDIR)
    with open(CURRENTDIR + r'configs/config.cfg', 'r') as ymlfile:
        cfg = yaml.load(ymlfile)

    conn = handle_db()

    for query in cfg['queries']:
        put_tweets(cfg, query, conn)

    # Pull each URL from the t able
    urls = conn.execute('SELECT url FROM tweets WHERE url NOT LIKE "Null"')

    for url in urls:
        if url:
            positives, reference = create_rss(cfg, url)
            print(reference)
            conn.execute('UPDATE tweets SET scanned="True", positives=?, vt_link=? WHERE url=?', (int(positives),str(reference),str(url)))
        else:
            print('No url to parse')
            pass
if __name__ == "__main__":
    logger = logtweets.configure_logger('default', './logs/general.log')
    main()

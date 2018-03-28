import json
import logging
import os
import re
from collections import OrderedDict
from threading import RLock

CFG_PATH = '/opt/kirale/'
CFG_FILE = CFG_PATH + 'kibra.cfg'
# Default configuration
CFG = {'dongle_name': 'Test', 'dongle_commcred': 'KIRALE'}
# User configuration read from file
CFG_USER = {}

MUTEX = RLock()


def get(key):
    with MUTEX:
        if key not in CFG:
            return None
        else:
            return CFG[key]


def set(key, value):
    with MUTEX:
        # Only save to disk if value has changed
        if key not in CFG or CFG[key] is not value:
            CFG[key] = value
            logging.debug('Saving %s as %s.', key, value)

def delete(key):
    '''Delete the database element if it exists'''
    try:
        del CFG[key]
    except KeyError:
        pass

def has_keys(key_list):
    ''' Return True if all keys exist in CFG'''
    with MUTEX:
        for key in key_list:
            if key not in CFG:
                return False
    return True


def load():
    global CFG, CFG_USER
    with MUTEX:
        if os.path.isfile(CFG_FILE):
            logging.debug('Loading configuration file %s', CFG_FILE)
            with open(CFG_FILE, 'r') as json_db:
                CFG = json.load(json_db)
            CFG_USER = CFG.copy()
        else:
            logging.debug('Using default configuration.')
            os.makedirs(CFG_PATH, exist_ok=True)
            with open(CFG_FILE, 'w') as json_db:
                json.dump(CFG, json_db)


def dump():
    logging.debug('Exporting configuration')
    config = json.dumps(OrderedDict(sorted(CFG.items())), indent=2)
    return config


def save():
    '''Save persistent configuration information'''
    with MUTEX:
        config = CFG_USER
        config['dongle_name'] = CFG['dongle_name']
        config['dongle_commcred'] = CFG['dongle_commcred']
        config['dongle_serial'] = CFG['dongle_serial']
        if os.path.isfile(CFG_FILE):
            logging.debug('Saving configuration file %s', CFG_FILE)
            config = json.dumps(OrderedDict(sorted(config.items())), indent=2)
            with open(CFG_FILE, 'w') as file_:
                file_.write(config + '\n')


def find_in_file(file, prev_patt, follow_patt):
    ''' For a given file, find a text between two patterns'''
    if os.path.isfile(file):
        with open(file, 'r') as file_:
            data = file_.read()
            result = re.search(r'%s(.*)%s' % (prev_patt, follow_patt), data)
            if result != None:
                return result.group(1)


def del_from_file(file, start_patt, end_patt):
    ''' For a given file, remove a text between two patterns,
    including the patterns'''
    if os.path.isfile(file):
        with open(file, 'r+') as file_:
            data = file_.read()
            data = re.sub(
                r'%s(.*?)%s' % (start_patt, end_patt),
                '',
                data,
                flags=re.DOTALL)
            file_.seek(0)
            file_.truncate()
            file_.write(data)

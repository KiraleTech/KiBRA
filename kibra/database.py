import json
import logging
import os
import re
from collections import OrderedDict
from threading import RLock

import kibra
from kibra.thread import DEFS

DEF_COMMCRED = 'KIRALE'
DEF_DONGLENAME = 'Test'

CFG_PATH = '/opt/kirale/'
CFG_FILE = CFG_PATH + 'kibra.cfg'
LOG_FILE = CFG_PATH + 'kibra.log'
# Default configuration
CFG = {}
# User configuration read from file
CFG_USER = {}

MUTEX = RLock()

DB_ITEMS_TYPE = 0
DB_ITEMS_DEF = 1
DB_ITEMS_VALID = 2
DB_ITEMS_WRITE = 3
DB_ITEMS_PERS = 4
# TODO: change DB_ITEMS_WRITE for a callback to be used after changing the value
DB_ITEMS = {
    'action_coapserver': [str, None, lambda x: True, True, False],
    'action_dhcp': [str, None, lambda x: True, True, False],
    'action_diags': [str, None, lambda x: True, True, False],
    'action_dns': [str, None, lambda x: True, True, False],
    'action_kibra': [str, None, lambda x: True, True, False],
    'action_mdns': [str, None, lambda x: True, True, False],
    'action_nat': [str, None, lambda x: True, True, False],
    'action_network': [str, None, lambda x: True, True, False],
    'action_serial': [str, None, lambda x: True, True, False],
    'action_syslog': [str, None, lambda x: True, True, False],
    'all_domain_bbrs': [str, None, lambda x: True, True, False],
    'all_network_bbrs': [str, None, lambda x: True, True, False],
    'autostart': [int, 0, lambda x: x in (0, 1), True, False],
    'bagent_port': [int, DEFS.PORT_MC, lambda x: True, False, False],
    'bbr_port': [int, DEFS.PORT_BB, lambda x: x >= 0 and x < 0xFFFF, False, False],
    'bbr_seq': [int, DEFS.BBR_SEQ, lambda x: x >= 0 and x < 0xFF, False, True],
    'bbr_status': [str, None, lambda x: True, False, False],
    'bridging_mark': [int, None, lambda x: True, False, False],
    'bridging_table': [str, None, lambda x: True, False, False],
    'dua_next_status': [str, '', lambda x: True, False, False],  # Thread Harness
    'dua_next_status_eid': [str, '', lambda x: True, False, False],  # Thread Harness
    'dongle_channel': [int, None, lambda x: True, True, False],
    'dongle_commcred': [str, DEF_COMMCRED, lambda x: True, True, True],
    'dongle_heui64': [str, None, lambda x: True, True, False],
    'dongle_mleid': [str, None, lambda x: True, False, False],
    'dongle_eid_cache': [list, '[]', lambda x: True, True, False],
    'dongle_emac': [str, None, lambda x: True, True, False],
    'dongle_ll': [str, None, lambda x: True, False, False],
    'dongle_mac': [str, None, lambda x: True, False, False],
    'dongle_name': [str, DEF_DONGLENAME, lambda x: True, True, True],
    'dongle_netkey': [str, None, lambda x: True, True, False],
    'dongle_netname': [str, None, lambda x: True, True, False],
    'dongle_outband': [str, None, lambda x: True, True, False],
    'dongle_panid': [str, None, lambda x: True, True, False],
    'dongle_prefix': [str, None, lambda x: True, True, False],
    'dongle_rloc': [str, None, lambda x: True, False, False],
    'dongle_role': [str, 'leader', lambda x: True, True, False],
    'dongle_serial': [str, None, lambda x: True, False, True],
    'dongle_secpol': [str, None, lambda x: True, False, False],
    'dongle_status': [str, None, lambda x: True, False, False],
    'dongle_xpanid': [str, None, lambda x: True, True, False],
    'exterior_ifname': [str, None, lambda x: True, False, False],
    'exterior_ifnumber': [int, None, lambda x: True, False, False],
    'exterior_addrs': [list, '[]', lambda x: True, False, False],
    'exterior_ipv6_ll': [str, None, lambda x: True, False, False],
    'exterior_mac': [str, None, lambda x: True, False, False],
    'exterior_port_mc': [int, 61001, lambda x: True, False, False],
    'interior_ifname': [str, None, lambda x: True, False, False],
    'interior_ifnumber': [int, None, lambda x: True, False, False],
    'interior_mac': [str, None, lambda x: True, False, False],
    'kibra_vendor': [str, kibra.__vendor__, lambda x: True, False, False],
    'kibra_model': [str, kibra.__model__, lambda x: True, False, False],
    'kibra_version': [
        str,
        'KiBRA v%s' % kibra.__version__,
        lambda x: True,
        False,
        False,
    ],
    'maddrs_perm': [list, '[]', lambda x: True, False, False],
    'mcast_admin_fwd': [int, 1, lambda x: x in (0, 1), True, False],
    'mcast_out_fwd': [int, 1, lambda x: x in (0, 1), True, False],
    'mlr_cache': [dict, '{}', lambda x: True, False, False],
    'mlr_timeout': [
        int,
        DEFS.BBR_DEF_MLR_TIMEOUT,
        lambda x: x >= 300 and x < 0xFFFFFFFF,
        True,
        True,
    ],
    'prefix': [str, None, lambda x: True, True, True],
    'prefix_active': [int, 0, lambda x: True, True, True],
    'prefix_dhcp': [int, 0, lambda x: True, True, True],
    'prefix_dua': [int, 0, lambda x: True, True, True],
    'prefix_slaac': [int, 1, lambda x: True, True, True],
    'rereg_delay': [
        int,
        DEFS.BBR_DEF_REREG_DELAY,
        lambda x: x >= 1 and x < 0xFFFF,
        True,
        True,
    ],
    'serial_device': [str, None, lambda x: True, False, False],
    'status_coapserver': [str, None, lambda x: True, False, False],
    'status_dhcp': [str, None, lambda x: True, False, False],
    'status_diags': [str, None, lambda x: True, False, False],
    'status_dns': [str, None, lambda x: True, False, False],
    'status_kibra': [str, None, lambda x: True, False, False],
    'status_mdns': [str, None, lambda x: True, False, False],
    'status_nat': [str, None, lambda x: True, False, False],
    'status_network': [str, None, lambda x: True, False, False],
    'status_serial': [str, None, lambda x: True, False, False],
    'status_syslog': [str, None, lambda x: True, False, False],
}


def modifiable_keys():
    return [x for x in DB_ITEMS.keys() if DB_ITEMS[x][DB_ITEMS_WRITE]]


def get(key):
    if not key in DB_ITEMS.keys():
        raise Exception('Trying to use a non existing DB entry key (%s).' % key)
    with MUTEX:
        if key not in CFG:
            return None
        else:
            value = CFG[key]
            type_ = DB_ITEMS[key][DB_ITEMS_TYPE]
            if type_ is int:
                return int(value)
            elif type_ is list:
                return list(json.loads(value.replace("'", '"')))
            elif type_ is dict:
                return dict(json.loads(value.replace("'", '"')))
            else:
                return value


def set(key, value):
    value = str(value)
    with MUTEX:
        # Only save if value has changed
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
                try:
                    CFG = json.load(json_db)
                except json.decoder.JSONDecodeError:
                    logging.error(
                        'Configuration file syntax error, using default configuration.'
                    )
            CFG_USER = CFG.copy()
        else:
            logging.debug('Using default configuration.')
            os.makedirs(CFG_PATH, exist_ok=True)
            with open(CFG_FILE, 'w') as json_db:
                json.dump(CFG, json_db)

    # Set default missing values
    for key in DB_ITEMS.keys():
        def_val = DB_ITEMS[key][DB_ITEMS_DEF]
        if def_val != None and not has_keys([key]):
            set(key, def_val)

    # Save modified file
    save()


def dump():
    logging.debug('Exporting configuration')
    config = json.dumps(OrderedDict(sorted(CFG.items())), indent=2)
    return config


def save():
    '''Save persistent configuration information'''
    with MUTEX:
        config = CFG_USER
        # Collect persistent values
        for key in DB_ITEMS.keys():
            if DB_ITEMS[key][DB_ITEMS_PERS]:
                if key in CFG:
                    config[key] = CFG[key]
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
                r'%s(.*?)%s' % (start_patt, end_patt), '', data, flags=re.DOTALL
            )
            file_.seek(0)
            file_.truncate()
            file_.write(data)

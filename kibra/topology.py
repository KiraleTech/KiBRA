import logging
from threading import Thread

import kibra.database as db
from kitools import kiserial

PRATE = 5
TIMEOUT = 240


def _get_devices(br_serial):
    logging.info('Looking for devices...')
    dongles = []
    brouter = kiserial.find_devices(has_br=True, has_snum=br_serial)[0]
    brouter = kiserial.KiSerial(brouter.port, debug=kiserial.KiDebug(1))
    devices = kiserial.find_devices()
    for dev in devices:
        if not dev.snum in br_serial:
            dongles.append(
                kiserial.KiSerial(dev.port, debug=kiserial.KiDebug(1)))
    logging.info('%d devices found' % len(dongles))
    return brouter, dongles


def _str2bin(s):
    return str(s) if s <= 1 else _str2bin(s >> 1) + str(s & 1)


def _get_atimestamp(auth=False):
    from time import time
    epoch = time()
    seconds = _str2bin(int(epoch)).zfill(48)
    ticks = _str2bin(int((epoch - int(epoch)) * 32768)).zfill(15)
    U = '1' if auth else '0'
    iATS = int(seconds + ticks + U, 2)
    return '0x' + hex(iATS).rstrip('L').replace('0x', '').zfill(16)


def _get_oobcom(brouter):
    try:
        if brouter.ksh_cmd('show status')[0] != 'joined':
            return None
    except:
        print('%s is busy' % brouter.port.port)
        return None

    oobcom = {}
    settings = brouter.ksh_cmd('show netconfig')
    for line in settings:
        if '| Channel' in line:
            oobcom['channel'] = line.split(':')[-1].strip()
        elif '| PAN ID' in line:
            oobcom['panid'] = line.split(':')[-1].strip()
        elif '| Extended PAN ID' in line:
            oobcom['xpanid'] = ''.join(line.split()[5:9])
        elif '| Network Name' in line:
            oobcom['netname'] = '"%s"' % line.split(':')[1].strip()
        elif '| Mesh-Local ULA' in line:
            oobcom['mlprefix'] = line.split(' : ')[-1].split('/')[0]
        elif '| Active Timestamp' in line:
            oobcom['actstamp'] = line.split(':')[-1].strip()
        elif '| Master Key' in line:
            oobcom['mkey'] = line.split(':')[-1].strip()
    oobcom['commcred'] = '"%s"' % db.get('dongle_commcred')

    return oobcom


def _join_network(dev, role, oobcom):
    logging.info('Adding %s to the network as %s' % (dev.name, role))
    if dev.ksh_cmd('show status', True)[0] != 'none':
        dev.ksh_cmd('debug level none', True)
        dev.ksh_cmd('clear')
        dev.wait_for('status', ['none'])
    dev.ksh_cmd('config outband')
    dev.ksh_cmd('config legacy off')
    for key, param in oobcom.items():
        dev.ksh_cmd('config %s %s' % (key, param))
    dev.ksh_cmd('config seqguard 0')
    if role == 'sed':
        dev.ksh_cmd('config pollrate %u' % PRATE)
    if role == 'leader' or role == 'reed':
        dev.ksh_cmd('config sjitter 1')
    dev.ksh_cmd('config role %s' % role)
    dev.ksh_cmd('ifup')
    dev.wait_for('status', ['joined'])
    dev.wait_for('role', [role, 'leader'])


def _stop_topology(dev):
    logging.info('Removing %s from the network' % dev.name)
    dev.ksh_cmd('clear')
    dev.wait_for('status', ['none'])


def form_topology():
    db.load()
    brouter, dongles = _get_devices(db.get('dongle_serial'))
    threads = []

    oobcom = _get_oobcom(brouter)
    if oobcom:
        oobcom['timeout'] = TIMEOUT
        for device in dongles:
            mac = device.ksh_cmd('show eui64', True)[0]
            device.set_mac(mac)
            # oobcom['actstamp'] = _get_atimestamp()
            threads.append(
                Thread(target=_join_network, args=[device, 'fed', oobcom]))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def clear_topology():
    db.load()
    _, dongles = _get_devices(db.get('dongle_serial'))
    threads = []

    for device in dongles:
        threads.append(Thread(target=_stop_topology, args=[device]))

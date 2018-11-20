import logging
import struct
from time import sleep

from kitools import kiserial

import kibra.database as db
from kibra.ktask import Ktask
from kibra.network import dongle_conf
from kibra.tlv import ThreadTLV
from kibra.thread import TLV

SERIAL_DEV = None


def _find_device(snum):
    '''Find the serial device with the required serial number'''
    if snum:
        logging.info('Trying to find device with serial %s.', snum)
        kirale_devs = kiserial.find_devices(has_snum=snum)
        if kirale_devs:
            return kirale_devs[0].port
    # Attempt to find any attached KiNOS device
    logging.info('Trying to find a KiNOS device...')
    kirale_devs = kiserial.find_devices(has_br=True)
    if kirale_devs:
        logging.info('KiNOS device was found on %s!', kirale_devs[0].port)
        return kirale_devs[0].port
    raise Exception('Error: No KiNOS devices found.')


def _enable_ecm():
    '''Find the device and initialize the port'''
    global SERIAL_DEV

    # Find device and initialize port
    port = _find_device(db.get('dongle_serial'))
    logging.info('Serial device is %s.', port)
    db.set('serial_device', port)
    SERIAL_DEV = kiserial.KiSerial(port, debug=kiserial.KiDebug(1))
    SERIAL_DEV.ksh_cmd('debug level none', debug_level=kiserial.KiDebug.NONE)

    # Save serial number
    db.set('dongle_serial', SERIAL_DEV.ksh_cmd('show snum')[0])

    # Enable ECM if not enabled
    if 'off' in SERIAL_DEV.ksh_cmd('show hwconfig')[3]:
        logging.info('Enabling CDC Ethernet and reseting device.')
        SERIAL_DEV.ksh_cmd('config hwmode 4')
        SERIAL_DEV.ksh_cmd('reset')
        sleep(0.5)
        del SERIAL_DEV
        _enable_ecm()


def _dongle_apply_config():
    # Config network parameters
    SERIAL_DEV.ksh_cmd('config legacy off') # Enable Thread 1.2
    if 'dongle_channel' in db.CFG:
        logging.info('Configure dongle channel %s.', db.get('dongle_channel'))
        SERIAL_DEV.ksh_cmd('config channel %s' % db.get('dongle_channel'))
    if 'dongle_panid' in db.CFG:
        logging.info('Configure dongle panid %s.', db.get('dongle_panid'))
        SERIAL_DEV.ksh_cmd('config panid %s' % db.get('dongle_panid'))
    if 'dongle_netname' in db.CFG:
        logging.info('Configure dongle network name %s.',
                     db.get('dongle_netname'))
        SERIAL_DEV.ksh_cmd('config netname "%s"' % db.get('dongle_netname'))
    if 'dongle_commcred' in db.CFG:
        logging.info('Configure dongle comissioner credential %s.',
                     db.get('dongle_commcred'))
        SERIAL_DEV.ksh_cmd('config commcred "%s"' % db.get('dongle_commcred'))
    role = db.get('dongle_role') or 'leader'
    logging.info('Set dongle as %s.', role)
    SERIAL_DEV.ksh_cmd('config role %s' % role)


def _configure():
    global SERIAL_DEV

    # Wait for the dongle to reach a steady status
    logging.info('Waiting until dongle is joined...')
    db.set('dongle_status', 'disconnected')
    dongle_status = ''
    while not ('none' in dongle_status or 'joined' in dongle_status):
        dongle_status = SERIAL_DEV.ksh_cmd(
            'show status', debug_level=kiserial.KiDebug.NONE)[0]
        sleep(1)

    # Different actions according to dongle status
    if dongle_status == 'none':
        _dongle_apply_config()
        SERIAL_DEV.ksh_cmd('ifup')
        _configure()
    elif dongle_status == 'none - saved configuration':
        SERIAL_DEV.ksh_cmd('ifup')
        _configure()
    elif dongle_status == 'joined':
        pass
    else:  # Other 'none' statuses
        logging.warning('Dongle status was "%s".' % dongle_status)
        SERIAL_DEV.ksh_cmd('clear')
        _configure()

    # Wait until the dongle is a router
    logging.info('Waiting until dongle becomes router...')
    db.set('dongle_role', 'none')
    # Selection jitter 120 s
    SERIAL_DEV.wait_for('role', ['router', 'leader'])

    # A non-router device can't be border router
    if SERIAL_DEV.ksh_cmd('show role')[0] not in ('router', 'leader'):
        SERIAL_DEV.ksh_cmd('clear')
        SERIAL_DEV.wait_for('status', ['none'])
        _configure()


def _dongle_get_config():
    db.set('dongle_role', SERIAL_DEV.ksh_cmd('show role')[0])
    db.set('dongle_status', SERIAL_DEV.ksh_cmd('show status')[0])

    # Get mesh rloc and link local addresses
    addrs = SERIAL_DEV.ksh_cmd('show ipaddr')
    for ip6_addr in addrs:
        if ip6_addr.startswith('ff'):
            # KiNOS registers multicast addresses with MLR.req
            continue
        elif ip6_addr.startswith('fe80'):
            db.set('dongle_ll', ip6_addr.strip('\r\n'))
            logging.info('Link local address is %s.', db.get('dongle_ll'))
        else:
            if 'ff:fe' in ip6_addr:
                db.set('dongle_rloc', ip6_addr.strip('\r\n'))
                logging.info('RLOC address is %s.', db.get('dongle_rloc'))
            else:
                # TODO: check prefix
                db.set('dongle_eid', ip6_addr.strip('\r\n'))
                logging.info('EID address is %s.', db.get('dongle_eid'))
    if not db.has_keys(['dongle_rloc']):
        raise Exception('Error: Mesh RLOC not found.')


def _enable_br():
    '''Enable CDC ETH traffic and announce prefix'''
    SERIAL_DEV.ksh_cmd('config brouter on')
    logging.info('Border router has been enabled.')

    THREAD_ENTERPRISE_NUMBER = 44970
    THREAD_SERVICE_DATA_BBR = '01'
    BBR_DEF_SEQ_NUM = 0
    BBR_DEF_REREG_DELAY = 4*1000
    BBR_DEF_MLR_TIMEOUT = 3600

    # Build s_server_data
    bbr_sequence_number = db.get('bbr_seq') or BBR_DEF_SEQ_NUM
    registration_delay = db.get('rereg_delay') or BBR_DEF_REREG_DELAY
    mlr_timeout = db.get('mlr_timeout') or BBR_DEF_MLR_TIMEOUT
    s_server_data = struct.pack('!BII', bbr_sequence_number,
                                registration_delay, mlr_timeout)

    # Enable BBR
    SERIAL_DEV.ksh_cmd('config service add %u %s %s' %
                       (THREAD_ENTERPRISE_NUMBER, THREAD_SERVICE_DATA_BBR,
                        bytes(s_server_data).hex()))
    logging.info('BBR has been enabled.')


def dhcp_on():
    ''''Announce DHCP prefix'''
    prefix = db.get('dhcp_pool')
    pool = prefix.split('/')[0]
    length = prefix.split('/')[1]
    # Flags: dhcp, stable (no on-mesh), DNS
    SERIAL_DEV.ksh_cmd('config prefix add ' + pool + ' ' + length + ' 0x0B01')
    logging.info('Prefix %s/%s has been announced to the Thread network.',
                 pool, length)


def dhcp_off():
    prefix = db.get('dhcp_pool')
    pool = prefix.split('/')[0]
    length = prefix.split('/')[1]
    SERIAL_DEV.ksh_cmd('config prefix remove ' + pool + ' ' + length +
                       ' 0x0B01')
    logging.info('Prefix %s/%s has been removed from the Thread network.',
                 pool, length)


def nat_on():
    # Flags: stable (no on-mesh)
    SERIAL_DEV.ksh_cmd('config route add 64:ff9b:: 96 0x0001')
    logging.info(
        'Prefix 64:ff9b::/96 has been announced to the Thread network.')


def nat_off():
    SERIAL_DEV.ksh_cmd('config route remove 64:ff9b:: 96 0x0001')
    logging.info(
        'Prefix 64:ff9b::/96 has been removed from the Thread network.')


def _bagent_on():
    SERIAL_DEV.ksh_cmd('config bagent on')
    logging.info('Border agent has been enabled.')


def _bagent_off():
    SERIAL_DEV.ksh_cmd('config bagent off')
    logging.info('Border agent has been disabled.')


class SERIAL(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='serial',
            start_keys=[],
            stop_tasks=['nat', 'diags'],
            period=2)

    def kstart(self):
        _enable_ecm()
        dongle_conf()
        _configure()
        _dongle_get_config()
        _enable_br()
        # _bagent_on()

    def kstop(self):
        # _bagent_off()
        SERIAL_DEV.ksh_cmd('ifdown')

    async def periodic(self):
        # Detect if serial was disconnected
        try:
            SERIAL_DEV.is_active()
        except IOError:
            logging.error('Device %s has been disconnected.',
                          db.get('serial_device'))
            self.kstop()
            self.kill()

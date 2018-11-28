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
    SERIAL_DEV.ksh_cmd('config legacy off')  # Enable Thread 1.2
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
    '''Enable CDC ETH traffic'''
    SERIAL_DEV.ksh_cmd('config brouter on')
    logging.info('Border router has been enabled.')


def bbr_dataset_update():
    '''
    Update Thread BBR Service Data
    Automatically increases the sequence number
    '''
    THREAD_ENTERPRISE_NUMBER = 44970
    THREAD_SERVICE_DATA_BBR = '01'
    THREAD_SERVICE_DATA_FMT = '!BHI'
    BBR_DEF_SEQ_NUM = 0
    BBR_DEF_REREG_DELAY = 4
    BBR_DEF_MLR_TIMEOUT = 3600

    # Increase sequence number
    bbr_sequence_number = db.get('bbr_seq') or BBR_DEF_SEQ_NUM
    bbr_sequence_number = (bbr_sequence_number + 1) % 0xff

    # Build s_server_data
    reregistration_delay = db.get('rereg_delay') or BBR_DEF_REREG_DELAY
    mlr_timeout = db.get('mlr_timeout') or BBR_DEF_MLR_TIMEOUT
    s_server_data = struct.pack(THREAD_SERVICE_DATA_FMT, bbr_sequence_number,
                                reregistration_delay, mlr_timeout)

    # Store used values
    db.set('bbr_seq', bbr_sequence_number)
    db.set('rereg_delay', reregistration_delay)
    db.set('mlr_timeout', mlr_timeout)

    # Enable BBR
    SERIAL_DEV.ksh_cmd('config service add %u %s %s' %
                       (THREAD_ENTERPRISE_NUMBER, THREAD_SERVICE_DATA_BBR,
                        bytes(s_server_data).hex()))
    logging.info('BBR update: Seq. = %d MLR Timeout = %d, Rereg. Delay = %d' %
                 (bbr_sequence_number, mlr_timeout, reregistration_delay))


def prefix_handle(
        type_: str,  # 'prefix' or 'route'
        action: str,  # 'add' or 'remove'
        prefix: str,  # 'prefix/length'
        stable=False,
        on_mesh=False,
        preferred=False,
        slaac=False,
        dhcp=False,
        configure=False,
        default=False,
        preference='medium',
        nd_dns=False,
        dp=False):
    '''
    5.18.3 Border Router TLV, 16 bits of flags:
    0 - Reserved --> Used by Kirale command to indicate Stable
    1 - Reserved
    2 - Reserved
    3 - Reserved
    4 - Reserved
    5 - Reserved
    6 - DP
    7 - ND DNS
    8 - On Mesh
    9 - Default
    10 - Configure
    11 - DHCP
    12 - SLAAC
    13 - Preferred
    14 - Preference
    15 - Preference
    '''
    flags = 0x0000
    if stable:
        flags |= 1 << 0
    if on_mesh:
        flags |= 1 << 8
    if preferred:
        flags |= 1 << 13
    if slaac:
        flags |= 1 << 12
    if dhcp:
        flags |= 1 << 11
    if configure:
        flags |= 1 << 10
    if default:
        flags |= 1 << 9
    if nd_dns:
        flags |= 1 << 7
    if dp and not slaac:
        flags |= 1 << 6
    if preference == 'high':
        flags |= 1 << 14
    elif preference == 'low':
        flags |= 3 << 14

    flags = '0x' + str(hex(flags).replace('0x', '').zfill(4))
    pool, length = prefix.split('/')

    SERIAL_DEV.ksh_cmd(
        'config %s %s %s %s %s' % (type_, action, pool, length, flags))
    logging.info('Config %s %s %s/%s', type_, action, pool, length)


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
        bbr_dataset_update()
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

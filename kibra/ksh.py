import logging
import os
import struct
import sys
import time

import importlib_resources
import kibra
import kibra.database as db
from kibra.ktask import Ktask
from kibra.network import dongle_conf, dongle_route_enable
from kibra.shell import bash
from kibra.thread import DEFS, TLV
from kibra.tlv import ThreadTLV
from kitools import kidfu, kifwu, kiserial

NCP_FW_FOLDER = 'kibra.ncp_fw'

SERIAL_DEV = None


def send_cmd(cmd, debug_level=None):
    logging.info(cmd)
    resp = SERIAL_DEV.ksh_cmd(cmd, debug_level)
    logging.info('\n'.join(resp))
    return resp


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
    logging.error('No KiNOS devices found.')
    sys.exit()


def ncp_fw_update():
    '''
    Compare the NCP firmware with the one available in the 'ncp_fiwmare' folder 
    and update if needed
    '''

    # Find the DFU file that matches the required fw version
    dfu_file = None
    ver_num = kibra.__kinosver__.split(' v')[-1]
    for file_name in importlib_resources.contents(NCP_FW_FOLDER):
        if ver_num in file_name:
            # TODO: This relies on the file name, we could also check the file
            # contents to make sure
            dfu_file = file_name
            break
    if not dfu_file:
        logging.error('Required NCP firmware not present.')
        sys.exit()

    # Flash the NCP and re-enable it
    with importlib_resources.path(NCP_FW_FOLDER, dfu_file) as dfu_path:
        logging.warn('NCP will be updated with firmware v%s' % ver_num)
        try:
            dfu_file = kidfu.DfuFile(str(dfu_path))
            kifwu.dfu_find_and_flash(dfu_file, unattended=True)
            # TODO: Remove this when KiTools is fixed for a proper USB re-enumeration
            # Reset USB device in KTBRN1
            bash('sh -c "echo 0 > /sys/bus/usb/devices/6-1/authorized"')
            bash('sh -c "echo 1 > /sys/bus/usb/devices/6-1/authorized"')
        except Exception as exc:
            logging.error('Problem updating NCP firmware: %s' % exc)
            sys.exit()

    logging.info('NCP updated successfully.')


def enable_ncp():
    '''Find the device and initialize the port'''
    global SERIAL_DEV

    # Find device and initialize port
    port = _find_device(db.get('dongle_serial'))
    if not port:
        return
    logging.info('Serial device is %s.', port)
    db.set('serial_device', port)
    SERIAL_DEV = kiserial.KiSerial(port, debug=kiserial.KiDebug(kiserial.KiDebug.NONE))
    send_cmd('debug level none', debug_level=kiserial.KiDebug.NONE)

    # Save serial number
    serial = send_cmd('show snum')[0]
    db.set('dongle_serial', serial)

    # Update the NCP firmware if needed
    if kibra.__kinosver__ not in send_cmd('show swver')[-1]:
        logging.info('NCP needs a firmware update.')
        ncp_fw_update()
        enable_ncp()
    # No need to continue if NCP fw version is up to date
    else:
        logging.info('NCP firmware is up to date.')

        # Make sure we are running Thread v3 (1.2.0)
        if not kibra.__kinosver__:
            send_cmd('config thver 3')

        # Enable ECM if not enabled
        if 'off' in send_cmd('show hwconfig')[3]:
            logging.info('Enabling CDC Ethernet and reseting device.')
            send_cmd('config hwmode 4')
            send_cmd('reset')
            time.sleep(3)
            del SERIAL_DEV
            enable_ncp()


def _dongle_apply_config():
    # Config network parameters
    if 'dongle_emac' in db.CFG:
        send_cmd('config emac %s' % db.get('dongle_emac'))
    if db.get('dongle_outband'):
        # TODO: make sure that the required settings exist
        send_cmd('config outband')
    if 'dongle_xpanid' in db.CFG:
        send_cmd('config xpanid %s' % db.get('dongle_xpanid'))
    if 'dongle_netkey' in db.CFG:
        send_cmd('config mkey %s' % db.get('dongle_netkey'))
    if 'dongle_prefix' in db.CFG:
        send_cmd('config mlprefix %s' % db.get('dongle_prefix').split('/')[0])
    if 'dongle_channel' in db.CFG:
        logging.info('Configure dongle channel %s.', db.get('dongle_channel'))
        send_cmd('config channel %s' % db.get('dongle_channel'))
    if 'dongle_panid' in db.CFG:
        logging.info('Configure dongle panid %s.', db.get('dongle_panid'))
        send_cmd('config panid %s' % db.get('dongle_panid'))
    if 'dongle_netname' in db.CFG:
        logging.info('Configure dongle network name %s.', db.get('dongle_netname'))
        send_cmd('config netname "%s"' % db.get('dongle_netname'))
    if 'dongle_commcred' in db.CFG:
        logging.info(
            'Configure dongle comissioner credential %s.', db.get('dongle_commcred')
        )
        send_cmd('config commcred "%s"' % db.get('dongle_commcred'))

    # Set role
    role = db.get('dongle_role')
    logging.info('Set dongle as %s.', role)
    send_cmd('config role %s' % role)


def _configure():
    global SERIAL_DEV

    dongle_status = send_cmd('show status', debug_level=kiserial.KiDebug.NONE)[0]

    # Wait for the dongle to reach a steady status
    logging.info('Waiting until dongle is joined...')
    db.set('dongle_status', 'disconnected')
    dongle_status = ''
    while not ('none' in dongle_status or 'joined' in dongle_status):
        dongle_status = send_cmd('show status', debug_level=kiserial.KiDebug.NONE)[0]
        time.sleep(1)

    # Different actions according to dongle status
    if dongle_status == 'none':
        if not kibra.__harness__:
            _dongle_apply_config()
        _enable_br()
        send_cmd('ifup')
        _configure()
    elif dongle_status == 'none - saved configuration':
        _enable_br()
        send_cmd('ifup')
        _configure()
    elif dongle_status == 'joined':
        pass
    else:  # Other 'none' statuses
        logging.warning('Dongle status was "%s".' % dongle_status)
        send_cmd('clear')
        _configure()


def _dongle_get_config():
    db.set('dongle_role', send_cmd('show role')[0])
    db.set('dongle_status', send_cmd('show status')[0])
    db.set('dongle_heui64', send_cmd('show heui64')[0])

    # Get mesh rloc and link local addresses
    all_addrs = send_cmd('show ipaddr')

    # Remove not registered addresses
    addrs = []
    for line in all_addrs:
        try:
            state, addr = line.split(' ')
            if state == '[R]':
                addrs.append(addr)
        except:
            # Old versions don't include registration information
            addrs.append(line)

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
                db.set('dongle_mleid', ip6_addr.strip('\r\n'))
                logging.info('EID address is %s.', db.get('dongle_mleid'))
    if not db.has_keys(['dongle_rloc']):
        raise Exception('Error: Mesh RLOC not found.')


def _enable_br():
    '''Enable CDC ETH traffic'''
    send_cmd('config brouter on')
    logging.info('Border router has been enabled.')


def bbr_dataset_update():
    '''
    Update Thread BBR Service Data
    Automatically increases the sequence number
    '''
    # Increase sequence number
    bbr_sequence_number = (db.get('bbr_seq') + 1) % 0xFF

    # Build s_server_data
    reregistration_delay = db.get('rereg_delay')
    mlr_timeout = db.get('mlr_timeout')
    s_server_data = struct.pack(
        DEFS.THREAD_SERVICE_DATA_FMT,
        bbr_sequence_number,
        reregistration_delay,
        mlr_timeout,
    )

    # Store used values
    db.set('bbr_seq', bbr_sequence_number)

    # Make them persistent
    db.save()

    # Enable BBR
    send_cmd(
        'config service add %u %s %s'
        % (
            DEFS.THREAD_ENTERPRISE_NUMBER,
            DEFS.THREAD_SERVICE_DATA_BBR,
            bytes(s_server_data).hex(),
        )
    )
    logging.info(
        'BBR update: Seq. = %d MLR Timeout = %d, Rereg. Delay = %d'
        % (bbr_sequence_number, mlr_timeout, reregistration_delay)
    )


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
    dp=False,
):
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

    send_cmd('config %s %s %s %s %s' % (type_, action, pool, length, flags))
    logging.info('Config %s %s %s/%s', type_, action, pool, length)


def _bagent_on():
    send_cmd('config bagent on')
    logging.info('Border agent has been enabled.')


def _bagent_off():
    send_cmd('config bagent off')
    logging.info('Border agent has been disabled.')


class SERIAL(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='serial',
            start_keys=['dongle_serial'],
            stop_tasks=['diags', 'coapserver'],
            period=2,
        )

    def kstart(self):
        db.set('prefix_active', 0)
        dongle_conf()
        _configure()
        _dongle_get_config()
        _bagent_on()

    def kstop(self):
        if db.get('prefix_active'):
            # Remove prefix from the network
            dp = True if db.get('prefix_dua') else False
            dhcp = True if db.get('prefix_dhcp') else False
            slaac = True if not dp and not dhcp else False

            prefix_handle(
                'prefix',
                'remove',
                db.get('prefix'),
                stable=True,
                on_mesh=True,
                default=True,
                slaac=slaac,
                dhcp=dhcp,
                dp=dp,
            )

            # Mark prefix as active
            db.set('prefix_active', 0)

        _bagent_off()
        send_cmd('ifdown')

    async def periodic(self):
        # Detect if serial was disconnected
        try:
            SERIAL_DEV.is_active()
        except IOError:
            logging.error('Device %s has been disconnected.', db.get('serial_device'))
            self.kstop()
            self.kill()

        if not db.get('prefix_active'):
            dp = True if db.get('prefix_dua') else False
            dhcp = True if db.get('prefix_dhcp') else False
            slaac = True if not dp and not dhcp else False

            # Don't continue if servers are not running
            if dhcp and db.get('status_dhcp') not in 'running':
                return
            if dp and db.get('status_coapserver') not in 'running':
                return

            # Add route
            dongle_route_enable(db.get('prefix'))

            # Announce prefix to the network
            prefix_handle(
                'prefix',
                'add',
                db.get('prefix'),
                stable=True,
                on_mesh=True,
                default=True,
                slaac=slaac,
                dhcp=dhcp,
                dp=dp,
            )

            bbr_dataset_update()

            # Mark prefix as active
            db.set('prefix_active', 1)

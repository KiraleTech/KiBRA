import logging
import os
import struct
import sys
import time

import importlib_resources
import kibra
import kibra.database as db
import kibra.network as NETWORK
from kibra.ktask import Ktask
from kibra.shell import bash
from kibra.thread import DEFS, TLV
from kibra.tlv import ThreadTLV
from kitools import kidfu, kifwu, kiserial

NCP_FW_FOLDER = 'kibra.ncp_fw'

SERIAL_DEV = None


def send_cmd(cmd, debug_level=None):
    logging.info(cmd)
    try:
        resp = SERIAL_DEV.ksh_cmd(cmd, debug_level)
    except:
        logging.error('Device %s is not responding.', db.get('serial_device'))
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
        except Exception as exc:
            logging.error('Problem updating NCP firmware: %s' % exc)
            sys.exit()

    logging.info('NCP updated successfully.')


def enable_ncp():
    '''Find the device and initialize the port'''
    global SERIAL_DEV

    # Find device and initialize port
    port = _find_device(db.get('ncp_serial'))
    if not port:
        return
    logging.info('Serial device is %s.', port)
    db.set('serial_device', port)
    SERIAL_DEV = kiserial.KiSerial(port, debug=kiserial.KiDebug(kiserial.KiDebug.NONE))
    send_cmd('debug level none', debug_level=kiserial.KiDebug.NONE)

    # Save serial number
    serial = send_cmd('show snum')[0]
    db.set('ncp_serial', serial)

    # Update the NCP firmware if needed
    if kibra.__kinosver__ not in send_cmd('show swver')[-1]:
        logging.info('NCP needs a firmware update.')
        ncp_fw_update()
        enable_ncp()
    # No need to continue if NCP fw version is up to date
    else:
        logging.info('NCP firmware is up to date.')

        # Make sure we are running Thread v3 (1.2.0)
        if not kibra.__harness__ and 'Thread v3' not in send_cmd('show thver')[0]:
            send_cmd('clear')
            SERIAL_DEV.wait_for('status', 'none')
            send_cmd('config thver 3')

        # Enable ECM if not enabled
        if 'off' in send_cmd('show hwconfig')[3]:
            logging.info('Enabling CDC Ethernet and reseting device.')
            send_cmd('config hwmode 4')
            send_cmd('reset')
            time.sleep(3)
            del SERIAL_DEV
            enable_ncp()


def _ncp_apply_config():
    # Config network parameters
    if 'ncp_emac' in db.CFG:
        send_cmd('config emac %s' % db.get('ncp_emac'))
    if db.get('ncp_outband'):
        # TODO: make sure that the required settings exist
        send_cmd('config outband')
    if 'ncp_xpanid' in db.CFG:
        send_cmd('config xpanid %s' % db.get('ncp_xpanid'))
    if 'ncp_netkey' in db.CFG:
        send_cmd('config mkey %s' % db.get('ncp_netkey'))
    if 'ncp_prefix' in db.CFG:
        send_cmd('config mlprefix %s' % db.get('ncp_prefix').split('/')[0])
    if 'ncp_channel' in db.CFG:
        logging.info('Configure NCP channel %s.', db.get('ncp_channel'))
        send_cmd('config channel %s' % db.get('ncp_channel'))
    if 'ncp_panid' in db.CFG:
        logging.info('Configure NCP panid %s.', db.get('ncp_panid'))
        send_cmd('config panid %s' % db.get('ncp_panid'))
    if 'ncp_netname' in db.CFG:
        logging.info('Configure NCP network name %s.', db.get('ncp_netname'))
        send_cmd('config netname "%s"' % db.get('ncp_netname'))
    if 'ncp_commcred' in db.CFG:
        logging.info(
            'Configure NCP comissioner credential %s.', db.get('ncp_commcred')
        )
        send_cmd('config commcred "%s"' % db.get('ncp_commcred'))

    # Set role
    role = db.get('ncp_role')
    logging.info('Set NCP as %s.', role)
    send_cmd('config role %s' % role)


def _configure():
    global SERIAL_DEV

    # Wait for the NCP to reach a steady status
    logging.info('Waiting until NCP is steady...')
    ncp_status = 'disconnected'
    while not ('none' in ncp_status or 'joined' in ncp_status):
        ncp_status = send_cmd('show status')[0]
        time.sleep(1)
    db.set('ncp_status', ncp_status)

    # Different actions according to NCP status
    if ncp_status == 'none':
        if not kibra.__harness__:
            _ncp_apply_config()
        _enable_br()
        send_cmd('ifup')
    elif ncp_status == 'none - saved configuration':
        _enable_br()
        send_cmd('ifup')
    elif ncp_status == 'joined':
        send_cmd('ifdown')
        _configure()
    else:  # Other 'none' statuses
        logging.warning('Dongle status was "%s".' % ncp_status)
        send_cmd('clear')
        SERIAL_DEV.wait_for('status', 'none')
        _configure()


def _enable_br():
    '''Enable CDC ETH traffic'''
    send_cmd('config brouter on')
    logging.info('CDC ETH traffic has been enabled.')


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
    if dp:
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


def _get_prefix_flags():
    slaac = True if db.get('prefix_slaac') else False
    dhcp = True if db.get('prefix_dhcp') else False
    dp = True if db.get('prefix_dua') else False

    # Force SLAAC if no other flags are set
    if not dp and not dhcp:
        slaac = True

    # DHCP overrides SLAAC
    if dhcp:
        slaac = False

    return slaac, dhcp, dp


class SERIAL(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='serial',
            start_keys=['ncp_serial'],
            start_tasks=['network', 'syslog'],
            stop_tasks=['diags', 'coapserver'],
            period=2,
        )

    def kstart(self):
        db.set('prefix_active', 0)
        db.set('ncp_heui64', send_cmd('show heui64')[0])
        _configure()
        # From now on the syslog daemon will detect changes

    def kstop(self):
        if db.get('prefix_active'):
            # Remove prefix from the network
            slaac, dhcp, dp = _get_prefix_flags()

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

            # Mark prefix as inactive
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
        except Exception:
            logging.error('Device %s is not responding.', db.get('serial_device'))
            return

        # Don't continue if device is not joined
        if db.get('ncp_status') != 'joined' or db.get('status_serial') != 'running':
            return

        if not db.get('prefix_active'):
            slaac, dhcp, dp = _get_prefix_flags()

            # Don't continue if servers are not running
            if dhcp and db.get('status_dhcp') not in 'running':
                return
            if dp and db.get('status_coapserver') not in 'running':
                return

            # Enable border agent
            _bagent_on()

            # Add route
            NETWORK.ncp_route_enable(db.get('prefix'))

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

            # Start as Secondary (KiNOS will notify the change to Primary)
            db.set('bbr_status', 'secondary')
            logging.info('This BBR is now Secondary.')

            # Announce service
            bbr_dataset_update()

            # Mark prefix as active
            db.set('prefix_active', 1)

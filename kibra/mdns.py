import logging
import pathlib
import socket
import struct

import kibra.database as db
from kibra.ktask import Ktask
from kibra.shell import bash

VENDOR_NAME = 'KiraleTechnologies'
DEVICE_NAME = 'KTBRN1'

MDNS_CONFIG = '/etc/avahi/avahi-daemon.conf'
MDNS_HOSTS = '/etc/avahi/hosts'
MDNS_SERVICES = '/etc/avahi/services'


def nat_start(action):
    '''
    natMdnsStart I -> Insert the rules
    natMdnsStart D -> Delete the rules
    '''
    # NAT 4 -> 6
    if db.has_keys(['exterior_ipv4']):
        if action == 'I':
            bash('jool --bib --add --udp ' + db.get('exterior_ipv4') + '#' +
                 str(db.get('exterior_port_mc')) + ' ' +
                 db.get('dongle_rloc') + '#' + str(db.get('bagent_port')) +
                 ' &> /dev/null')
        else:
            bash('jool --bib --remove --udp ' + db.get('exterior_ipv4') + '#' +
                 str(db.get('exterior_port_mc')) + ' ' +
                 db.get('dongle_rloc') + '#' + str(db.get('bagent_port')) +
                 ' &> /dev/null')
        # Mark MC packets before they are translated, so they are not consumed by Linux but by the dongle
        bash(
            'iptables -w -t mangle -%s PREROUTING -i %s -d %s -p udp --dport %d -j MARK --set-mark %s'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv4'),
               db.get('exterior_port_mc'), db.get('bridging_mark')))
    # NAT 6 -> 6
    if db.has_keys(['exterior_ipv6']):
        bash(
            'ip6tables -w -t nat -%s PREROUTING -i %s -d %s -p udp --dport %d -j DNAT --to [%s]:%d'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv6'),
               db.get('exterior_port_mc'), db.get('dongle_rloc'),
               db.get('bagent_port')))
        bash(
            'ip6tables -w -t nat -%s POSTROUTING -o %s -s %s -p udp --sport %d -j SNAT --to [%s]:%d'
            % (action, db.get('exterior_ifname'), db.get('dongle_rloc'),
               db.get('bagent_port'), db.get('exterior_ipv6'),
               db.get('exterior_port_mc')))
        bash(
            'ip6tables -w -t mangle -%s PREROUTING -i %s -d %s -p udp --dport %d -j MARK --set-mark %s'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv6'),
               db.get('exterior_port_mc'), db.get('bridging_mark')))


def get_records():
    records = {}

    '''Table 8-5. Border Agent State Bitmap'''
    CONNECTION_MODE = 0
    THREAD_INTERFACE_STATUS = 3
    AVAILABILITY = 5
    BBR_FUNCTION_ACTIVE = 7
    BBR_PRIMARY = 8

    DTLS_DISABLED = 0
    DTLS_PSKC = 1
    DTLS_PSKD = 2
    DTLS_VENDOR = 3
    DLTS_X509 = 4

    IFACE_OFF = 0
    IFACE_CFG = 1
    IFACE_UP = 2

    bitmap = 0x0

    # Connection mode
    security_policy = db.get('dongle_secpol')
    # Check C bit
    if security_policy and bytes.fromhex(security_policy)[2] >> 4 & 1:
        mode = DTLS_PSKC
    else:
        mode = DTLS_DISABLED
    bitmap |= mode << CONNECTION_MODE

    # Thread interface status
    dongle_status = db.get('dongle_status') or ''
    if 'joined' in dongle_status:
        status = IFACE_UP
        if mode == DTLS_PSKC:
            records['nn'] = db.get('dongle_netname')
            records['xp'] = db.get('dongle_xpanid').replace('0x', '')
    elif 'none - saved configuration' in dongle_status:
        status = IFACE_CFG
    else:
        status = IFACE_OFF
        if mode == DTLS_PSKC:
            records['nn'] = DEVICE_NAME
            # TODO: sha256
            records['xp'] = db.get('dongle_eui64')

    bitmap |= status << THREAD_INTERFACE_STATUS

    # Availability
    bitmap |= 1 << AVAILABILITY

    # BBR function
    bbr_status = db.get('bbr_status') or 'off'
    if not 'off' in bbr_status:
        bitmap |= 1 << BBR_FUNCTION_ACTIVE
        if 'primary' in bbr_status:
            bitmap |= 1 << BBR_PRIMARY
    
    records['sb'] = struct.pack('!I', bitmap).hex()
    records['vn'] = VENDOR_NAME
    records['mn'] = DEVICE_NAME
    records['sq'] = struct.pack('!I', db.get('bbr_seq')).hex()
    records['bb'] = struct.pack('!H', db.get('bbr_port')).hex()

    return records

class MDNS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='mdns',
            start_keys=[
                'exterior_ifname', 'dongle_netname',
                'dongle_xpanid', 'bbr_seq', 'bbr_port'
            ],
            stop_keys=['interior_ifname'],
            # Needs coapserver to have the BBR Dataset
            start_tasks=['network', 'coapserver'],
            period=2)

    async def periodic(self):
        self.service_update()

    def kstart(self):
        logging.info('Configuring Avahi daemon.')
        with open(MDNS_CONFIG, 'w') as file_:
            file_.write('[server]\n')
            file_.write('use-ipv4=%s\n' %
                        ('yes' if db.has_keys(['exterior_ipv4']) else 'no'))
            file_.write('use-ipv6=%s\n' %
                        ('yes' if db.has_keys(['exterior_ipv6']) else 'no'))
            file_.write('allow-interfaces=%s\n' % db.get('exterior_ifname'))
            file_.write('disallow-other-stacks=yes\n\n')
            file_.write('[publish]\n')
            file_.write('publish-addresses=yes\n')
            file_.write('publish-hinfo=no\n')
            file_.write('publish-workstation=no\n')
            file_.write('publish-domain=no\n')
            file_.write('publish-aaaa-on-ipv4=no\n')
            file_.write('publish-a-on-ipv6=no\n\n')
            file_.write('[rlimits]\n')
            file_.write('rlimit-core=0\n')
            file_.write('rlimit-data=4194304\n')
            file_.write('rlimit-fsize=0\n')
            file_.write('rlimit-nofile=30\n')
            file_.write('rlimit-stack=4194304\n')
            file_.write('rlimit-nproc=3\n')

        # Enable service
        self.service_update()

        # Enable NAT
        logging.info('Enabling Border Agent NAT.')
        nat_start('I')

    def kstop(self):
        # Disnable NAT
        logging.info('Disabling Border Agent NAT.')
        nat_start('D')

        # Disable service
        logging.info('Removing Avahi service.')
        bash('rm /etc/avahi/services/%s.service' % db.get('dongle_name'))
        bash('service avahi-daemon restart')

    def service_update(self):
        records = get_records()
        # Compose the new service data
        snw = ''
        snw += '<?xml version="1.0" encoding="utf-8" standalone="no"?>\n'
        snw += '<!DOCTYPE service-group SYSTEM "avahi-service.dtd">\n'
        snw += '<service-group>\n'
        snw += '  <name>%s %s %s</name>\n' % (db.get('dongle_name'), records['vn'], records['mn'])
        snw += '  <service>\n'
        snw += '      <type>_meshcop._udp</type>\n'
        snw += '      <host-name>%s.local</host-name>\n' % socket.gethostname()
        snw += '      <port>%d</port>\n' % db.get('exterior_port_mc')
        snw += '      <txt-record>rv=%s</txt-record>\n' % '1'
        snw += '      <txt-record>tv=%s</txt-record>\n' % '1.2.0'
        snw += '      <txt-record value-format="binary-hex">sb=%s</txt-record>\n' % records['sb']
        if records['nn']:
            snw += '      <txt-record>nn=%s</txt-record>\n' % records['nn']
        if records['xp']:
            snw += '      <txt-record value-format="binary-hex">xp=%s</txt-record>\n' % records['xp']
        snw += '      <txt-record>vn=%s</txt-record>\n' % records['vn']
        snw += '      <txt-record>mn=%s</txt-record>\n' % records['mn']
        if records['sq']:
            snw += '      <txt-record value-format="binary-hex">sq=%s</txt-record>\n' % records['sq']
        if records['bb']:
            snw += '      <txt-record value-format="binary-hex">bb=%s</txt-record>\n' % records['bb']
        snw += '  </service>\n'
        snw += '</service-group>\n'

        # Load the previous service file, or create it
        pathlib.Path(MDNS_SERVICES).mkdir(parents=True, exist_ok=True)
        service_file = '%s/%s.service' % (MDNS_SERVICES, db.get('dongle_name'))
        file_name = pathlib.Path(service_file)
        file_name.touch(exist_ok=True)

        with open(str(service_file), 'r') as file_:
            sod = file_.read()
        
        # Only restart service if something changed
        if snw != sod:
            with open(str(file_name), 'w') as file_:
                file_.write(snw)
            bash('service avahi-daemon restart')
            logging.info('mDNS service updated.')

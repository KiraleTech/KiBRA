import logging
import pathlib
import socket
import struct

import kibra.database as db
from kibra.ktask import Ktask
from kibra.shell import bash

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
            bash('jool bib add %s#%s %s#%s --udp' %
                 (db.get('exterior_ipv4'), str(db.get('exterior_port_mc')),
                  db.get('dongle_rloc'), str(db.get('bagent_port'))))
        else:
            bash('jool bib remove %s#%s %s#%s --udp' %
                 (db.get('exterior_ipv4'), str(db.get('exterior_port_mc')),
                  db.get('dongle_rloc'), str(db.get('bagent_port'))))
        # Mark MC packets before they are translated, so they are not consumed by Linux but by the dongle
        # Flush old rules first
        bash('iptables -F -t mangle')
        bash(
            'iptables -w -t mangle -%s PREROUTING -i %s -d %s -p udp --dport %d -j MARK --set-mark %s'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv4'),
               db.get('exterior_port_mc'), db.get('bridging_mark')))
    # NAT 6 -> 6
    if db.has_keys(['exterior_ipv6_ll']):
        bash(
            'ip6tables -w -t nat -%s PREROUTING -i %s -d %s -p udp --dport %d -j DNAT --to [%s]:%d'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv6_ll'),
               db.get('exterior_port_mc'), db.get('dongle_rloc'),
               db.get('bagent_port')))
        bash(
            'ip6tables -w -t nat -%s POSTROUTING -o %s -s %s -p udp --sport %d -j SNAT --to [%s]:%d'
            % (action, db.get('exterior_ifname'), db.get('dongle_rloc'),
               db.get('bagent_port'), db.get('exterior_ipv6_ll'),
               db.get('exterior_port_mc')))
        bash(
            'ip6tables -w -t mangle -%s PREROUTING -i %s -d %s -p udp --dport %d -j MARK --set-mark %s'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv6_ll'),
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
        if mode == DTLS_PSKC:
            records['nn'] = db.get('dongle_netname')
            records['xp'] = db.get('dongle_xpanid').replace('0x', '')
    else:
        status = IFACE_OFF
        if mode == DTLS_PSKC:
            records['nn'] = db.get('kibra_model')
            records['xp'] = db.get('dongle_heui64')

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
    records['vn'] = db.get('kibra_vendor')
    records['mn'] = db.get('kibra_model')
    records['sq'] = struct.pack('!I', db.get('bbr_seq')).hex()
    records['bb'] = struct.pack('!H', db.get('bbr_port')).hex()

    return records


class MDNS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='mdns',
            start_keys=['exterior_ifname', 'bbr_seq', 'bbr_port'],
            period=2)
        self.nat_enabled = False

    async def periodic(self):
        if not self.nat_enabled and db.get('status_nat') == 'running':
            # Enable NAT
            logging.info('Enabling Border Agent NAT.')
            self.nat_enabled = True
            nat_start('I')

        self.service_update()

    def kstart(self):
        logging.info('Configuring Avahi daemon.')
        ip4 = 'yes' if db.has_keys(['exterior_ipv4']) else 'no'
        ip6 = 'yes' if db.has_keys(['exterior_ipv6_ll']) else 'no'
        with open(MDNS_CONFIG, 'w') as file_:
            lines = []
            lines.append('[server]')
            lines.append('use-ipv4=%s' % ip4)
            lines.append('use-ipv6=%s' % ip6)
            lines.append('allow-interfaces=%s' % db.get('exterior_ifname'))
            lines.append('disallow-other-stacks=yes\n')
            lines.append('[publish]')
            lines.append('publish-addresses=yes')
            lines.append('publish-hinfo=no')
            lines.append('publish-workstation=no')
            lines.append('publish-domain=no')
            lines.append('publish-aaaa-on-ipv4=no')
            lines.append('publish-a-on-ipv6=no\n')
            lines.append('[rlimits]')
            lines.append('rlimit-core=0')
            lines.append('rlimit-data=4194304')
            lines.append('rlimit-fsize=0')
            lines.append('rlimit-nofile=30')
            lines.append('rlimit-stack=4194304')
            lines.append('rlimit-nproc=3')
            lines = '\n'.join(lines)
            file_.write(lines)

        # Enable service
        self.service_update()

    def kstop(self):
        if self.nat_enabled:
            # Disnable NAT
            logging.info('Disabling Border Agent NAT.')
            self.nat_enabled = False
            nat_start('D')

        # Disable service
        logging.info('Removing Avahi service.')
        bash('rm /etc/avahi/services/%s.service' % db.get('dongle_name'))
        bash('service avahi-daemon reload')

    def service_update(self):
        r_txt = '\t\t<txt-record>%s=%s</txt-record>'
        r_bin = '\t\t<txt-record value-format="binary-hex">%s=%s</txt-record>'

        try:
            records = get_records()
            hostname = socket.gethostname()
        except:
            logging.warning('Unable to get the mDNS records.')
            return
        # Compose the new service data
        snw = []
        snw.append('<?xml version="1.0" encoding="utf-8" standalone="no"?>')
        snw.append('<!DOCTYPE service-group SYSTEM "avahi-service.dtd">')
        snw.append('<service-group>')
        snw.append('\t<name>%s %s %s</name>' % (db.get('dongle_name'),
                                                records['vn'], records['mn']))
        snw.append('\t<service>')
        snw.append('\t\t<type>_meshcop._udp</type>')
        snw.append('\t\t<host-name>%s.local</host-name>' % hostname)
        snw.append('\t\t<port>%d</port>' % db.get('exterior_port_mc'))
        snw.append(r_txt % ('rv', '1'))
        snw.append(r_txt % ('tv', '1.2.0'))
        snw.append(r_bin % ('sb', records['sb']))
        snw.append(r_txt % ('vn', records['vn']))
        snw.append(r_txt % ('mn', records['mn']))
        if 'nn' in records.keys():
            snw.append(r_txt % ('nn', records['nn']))
        if 'xp' in records.keys():
            snw.append(r_bin % ('xp', records['xp']))
        if 'sq' in records.keys():
            snw.append(r_bin % ('sq', records['sq']))
        if 'bb' in records.keys():
            snw.append(r_bin % ('bb', records['bb']))
        snw.append('\t</service>')
        snw.append('</service-group>\n')
        snw = '\n'.join(snw)

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
            bash('service avahi-daemon reload')
            logging.info('mDNS service updated.')

import logging
import socket
import struct

import zeroconf

import kibra.database as db
from kibra.ktask import Ktask
from kibra.shell import bash

VENDOR_NAME = "KiraleTechnologies"
DEVICE_NAME = "KiraleBR"

# natMdnsStart I -> Insert the rules ; natMdnsStart D -> Delete the rules


def nat_start(action):
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


class MDNS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='mdns',
            start_keys=[
                'exterior_ifname', 'exterior_ipv4', 'dongle_netname',
                'dongle_xpanid', 'bbr_seq', 'bbr_port'
            ],
            stop_keys=['interior_ifname'],
            # Needs diags to have the latest xpanid
            # Needs coapserver to have
            start_tasks=['diags', 'network', 'coapserver'],
            period=5)

    def kstart(self):
        self.mdns = zeroconf.Zeroconf()
        self.service = None

        # Enable NAT
        logging.info('Enabling Border Agent NAT.')
        nat_start('I')

    def kstop(self):
        # Disnable NAT
        logging.info('Disabling Border Agent NAT.')
        nat_start('D')

        # Disable service
        logging.info('Removing mDNS service.')
        self.mdns.unregister_service(self.service)
        self.mdns.close()

    async def periodic(self):
        self.service_update()

    def service_update(self):
        props = {
            'rv': '1',
            'tv': '1.2.0',
            'sb': bytes([0, 0, 0, 0x82]),
            'nn': db.get('dongle_netname'),
            'xp': bytes.fromhex(db.get('dongle_xpanid').replace('0x', '')),
            'vn': VENDOR_NAME,
            'mn': DEVICE_NAME,
            'sq': struct.pack('!I', db.get('bbr_seq')),
            'bb': struct.pack('!H', db.get('bbr_port')),
        }

        if self.service:
            if props == self.service.properties:
                # Don't continue if nothing changed
                return
            else:
                # Remove previously announced service before adding it again
                self.mdns.unregister_service(self.service)

        # Announce the service with the new data
        type_ = '_meshcop._udp.local.'
        name = '%s %s %s' % (db.get('dongle_name'), VENDOR_NAME, DEVICE_NAME)
        self.service = zeroconf.ServiceInfo(
            type_=type_,
            name='%s.%s' % (name, type_),
            # TODO: Support for IPv6 backbone
            address=socket.inet_aton(db.get('exterior_ipv4')),
            port=db.get('exterior_port_mc'),
            properties=props)
        self.mdns.register_service(self.service)
        logging.info('mDNS service updated.')

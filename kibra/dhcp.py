from struct import pack
from time import sleep

import kitools

import kibra.database as db
import kibra.ksh as KSH
from kibra.ktask import Ktask
from kibra.network import dongle_route_disable, dongle_route_enable
from kibra.shell import bash

DHCP_CONFIG = '/etc/dibbler/server.conf'
DHCP_DAEMON = 'dibbler-server'


def ntp_server_opt(addr):
    '''Given a server address return the HEX formatted payload of DHCPv6 toption
       56 as RFC5908'''
    b_pload = pack('>H', 1)
    b_pload += pack('>H', 16)
    b_pload += kitools.kicmds.s2b(kitools.kicmds.TYP.ADDR, addr)
    return ':'.join([hex(byte).replace('0x', '').zfill(2) for byte in b_pload])


class DHCP(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='dhcp',
            start_keys=[
                'dhcp_pool', 'interior_ifname', 'dongle_rloc', 'interior_mac'
            ],
            stop_keys=['interior_ifname'],
            start_tasks=['network', 'serial'],
            period=2)

    def kstart(self):
        # Stop DHCP daemon
        bash(DHCP_DAEMON + ' stop')
        # Add route
        dongle_route_enable(db.get('dhcp_pool'))
        # Remove previous configuration for this dongle
        db.del_from_file(DHCP_CONFIG, '\niface %s' % db.get('interior_ifname'),
                         '\n}\n')
        # Add new configuration
        with open(DHCP_CONFIG, 'w') as file_:
            file_.write('\n')
            file_.write('iface ' + db.get('interior_ifname') + ' {\n')
            file_.write('\tclient-max-lease 1\n')
            file_.write('\tunicast ' + db.get('dongle_rloc') + '\n')
            file_.write('\trapid-commit yes\n')
            # file_.write('\toption 224 address ' + db.get('dongle_rloc') + '\n') # CoAP RD
            #file_.write('\toption 56 duid ' + ntp_server_opt(db.get('dongle_rloc')) + '\n')
            file_.write('\toption ntp-server ' + db.get('dongle_eid') + '\n')
            file_.write('\toption dns-server ' + db.get('dongle_eid') + '\n')
            file_.write('\tpreference 255\n')
            file_.write('\tclass {\n')
            file_.write('\t\tT1 0\n')
            file_.write('\t\tT2 0\n')
            file_.write('\t\tpreferred-lifetime 1500\n')
            file_.write('\t\tvalid-lifetime 1800\n')
            file_.write('\t\tpool ' + db.get('dhcp_pool') + '\n')
            file_.write('\t}\n')
            #file_.write('\tclient duid ' + db.get('dongle_mac') + ' {\n')
            #file_.write('\t\taddress ' + db.get('dhcp_server') + '\n')
            # file_.write('\t}\n')
            file_.write('}\n')
        # Allow for the file to be stored
        sleep(0.2)
        # Start DHCP daemon
        bash(DHCP_DAEMON + ' start')
        # Announce prefix in the Thread network
        KSH.prefix_handle(
            'prefix',
            'add',
            db.get('dhcp_pool'),
            stable=True,
            on_mesh=True,
            dhcp=True,
            default=True)

    def kstop(self):
        # Remove prefix from the Thread network# Announce prefix in the Thread network
        KSH.prefix_handle(
            'prefix',
            'remove',
            db.get('dhcp_pool'),
            stable=True,
            on_mesh=True,
            dhcp=True,
            default=True)
        # Stop DHCP daemon
        bash(DHCP_DAEMON + ' stop')
        # Remove previous configuration for this dongle
        db.del_from_file(DHCP_CONFIG, '\niface %s' % db.get('interior_ifname'),
                         '\n}\n')
        # Allow for the file to be stored
        sleep(0.2)
        # Remove route
        dongle_route_disable(db.get('dhcp_pool'))
        # Start DHCP daemon
        bash(DHCP_DAEMON + ' start')

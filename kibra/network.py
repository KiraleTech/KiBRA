import ipaddress
import logging
from socket import AF_INET, AF_INET6
from struct import pack, unpack
from time import time
from Cryptodome.Hash import SHA256
from pyroute2 import IPRoute  # http://docs.pyroute2.org/iproute.html#api

import kibra.database as db
import kibra.iptables as iptables
from kibra.shell import bash
from kibra.ktask import Ktask

DHCLIENT6_LEASES_FILE = '/var/lib/dhcp/dhclient6.leases'
BR_TABLE_NR = 200
IP = IPRoute()


def _global_netconfig():
    if not db.has_keys(['exterior_ifname']):
        db.set('exterior_ifname', _get_ext_ifname())
        logging.info('External interface is %s.', db.get('exterior_ifname'))
    if not db.has_keys(['prefix']):
        logging.info('Trying to obtain a prefix via Prefix Delegation...')
        prefix = _get_prefix(db.get('exterior_ifname'))
        if not prefix:
            logging.info('It was not possible to obtain a global prefix.')
            prefix = _get_ula()
            logging.info('Generated the ULA prefix %s.' % prefix)
        db.set('prefix', prefix)


def _get_ula():
    '''Generate a GUA as RFC4193'''
    # https://tools.ietf.org/html/rfc4193#section-3.2.2
    ntp_time = str(unpack('Q', pack('d', time()))[0])  # Time in hexadecimal
    eui64 = db.get('dongle_serial').split('+')[-1]  # EUI64
    sha = SHA256.new((ntp_time + eui64).encode()).hexdigest().zfill(
        40)  # SHA1 of Time + EUI64
    # fd + last 40 bits of SHA1
    ula = ipaddress.IPv6Address(
        int('fd' + sha[-10:] + '00000000000000000000', 16))
    return ula.compressed + '/48'


def _get_prefix(exterior_ifname):
    #TODO: Parse the leases file properly to make sure it is valid
    prefix = db.find_in_file(DHCLIENT6_LEASES_FILE, 'iaprefix ', ' {')
    if prefix:
        logging.info('Obtained global prefix %s', prefix)
        return prefix


def get_addr(ifname, family):
    '''Get and address for the interface'''
    # Find configured address
    idx = IP.link_lookup(ifname=ifname)[0]
    raw_addrs = IP.get_addr(family=family, scope=0, index=idx)
    if raw_addrs:
        return raw_addrs[0].get_attr('IFA_ADDRESS')
    '''
    # No configured address found, try DHCP
    if family == AF_INET:
        logging.info('No IPv4 addresses found, trying to obtain one via DHCP.')
        leases_file = '%sleases-ip4-%s' % (db.CFG_PATH, ifname)
        bash('dhclient -4 -lf %s %s 2> /dev/null' % (leases_file, ifname))
    if family == AF_INET6:
        logging.info('No IPv6 addresses found, trying to obtain one via DHCP.')
        leases_file = '%sleases-ip6-%s' % (db.CFG_PATH, ifname)
        bash('dhclient -6 -lf %s %s 2> /dev/null' % (leases_file, ifname))
    raw_addrs = IP.get_addr(family=family, scope=0, index=idx)
    if raw_addrs:
        addr = raw_addrs[0].get_attr('IFA_ADDRESS')
        return addr
    '''


def _get_ext_ifname():
    '''Return the name of the interface with the default IPv4 route'''
    def_routes = IP.get_default_routes(AF_INET)
    if not def_routes:
        raise Exception('No external interfaces found.')
    index = def_routes[0].get_attr('RTA_OIF')
    return IP.get_links(index)[0].get_attr('IFLA_IFNAME')
    # Old:
    #Return the name of the first active interface found
    #for link in IP.get_links():
    #    if 'UP' in link.get_attr('IFLA_OPERSTATE'):
    #        return link.get_attr('IFLA_IFNAME')


def dongle_conf():
    '''Configure several network parameters'''
    # Find exterior interface and prefix
    _global_netconfig()
    # Detect exterior interface addresses
    ipv4 = get_addr(db.get('exterior_ifname'), AF_INET)
    if ipv4 != None:
        logging.info('Using %s as exterior IPv4 address.', ipv4)
        db.set('exterior_ipv4', ipv4)
    # ipv6 = get_addr(db.get('exterior_ifname'), AF_INET6)
    ipv6 = None
    if ipv6 != None:
        logging.info('Using %s as exterior IPv6 address.', ipv6)
        db.set('exterior_ipv6', ipv6)

    # By Kirale convention, interior MAC address is obtained from the dongle serial
    serial = db.get('dongle_serial').split('+')[-1]
    interior_mac = ':'.join([
        serial[0:2], serial[2:4], serial[4:6], serial[10:12], serial[12:14],
        serial[14:16]
    ])
    db.set('interior_mac', interior_mac)
    # Also dongle MAC is related to interior MAC
    dongle_mac = bytearray.fromhex(interior_mac.replace(':', ''))
    dongle_mac[0] |= 0x02
    db.set('dongle_mac', ':'.join(['%02x' % byte for byte in dongle_mac]))
    # Find the device with the configured MAC address
    links = IP.get_links(IFLA_ADDRESS=db.get('interior_mac').lower())
    if links:
        db.set('interior_ifname', links[0].get_attr('IFLA_IFNAME'))
        db.set('interior_ifnumber', links[0]['index'])
    else:
        raise Exception(
            'Error: Device not found with MAC ' + db.get('interior_mac'))

    # Use last 32 bits of interior MAC as bridging mark
    db.set('bridging_mark',
           int(db.get('interior_mac').replace(':', '')[-8:], 16))
    db.set('bridging_table', db.get('interior_mac'))
    db.set('bagent_port', 49191)
    db.set('exterior_port_mc', 20000 + int(db.get('interior_mac')[-2:], 16))

    # Load or generate the Pool4 prefix
    if not db.has_keys(['pool4']):
        # Default Kirale NAT IPv4 pool, with room for 64k nodes (>32*512).
        # Last byte of the interior MAC is used to compose the IPv4 network address
        db.set('pool4', '10.' +
               str(int(db.get('interior_mac').split(':')[-1], 16)) + '.0.0/16')
    elif int(db.get('pool4').split('/')[1]) % 8 != 0:
        raise Exception('Error: Pool4 prefix length must be a 8 multiple.')

    # Compose the DHCPv6 pool: global prefix + pool4
    if db.has_keys(['prefix']):
        net4 = ipaddress.ip_network(db.get('pool4'))
        net6 = ipaddress.ip_network(db.get('prefix'))
        shift = 2**(96 - net6.prefixlen)
        dhcp = ipaddress.ip_address(int(net6[0]) + shift * int(net4[0]))
        dhcp_pool = ipaddress.ip_network(
            str(dhcp) + '/' + str(net4.prefixlen + net6.prefixlen))
        db.set('dhcp_pool', str(dhcp_pool))


def _get_rt_tables():
    rt_tables = {}
    with open('/etc/iproute2/rt_tables', 'r') as file_:
        for line in file_.read().splitlines():
            fields = line.split()
            if fields and '#' not in fields[0]:
                rt_tables[fields[-1]] = int(fields[0])
    return rt_tables


def _rt_add_table(name, number):
    with open('/etc/iproute2/rt_tables', 'a') as file_:
        file_.write('\n%s\t%s\n' % (number, name))


def _ifup():
    # Make sure forwarding is enabled
    bash('sysctl -w net.ipv4.conf.all.forwarding=1')
    bash('sysctl -w net.ipv6.conf.all.forwarding=1')
    logging.info('Forwarding has been enabled.')

    # Disable duplicate address detection for the interior interface
    bash('sysctl -w net.ipv6.conf.%s.accept_dad=0' % db.get('interior_ifname'))
    logging.info('DAD has been disabled for %s.', db.get('interior_ifname'))

    # Bring interior interface up
    idx = db.get('interior_ifnumber')
    # First bring it down to remove old invalid addresses
    IP.link('set', index=idx, state='down')
    IP.link('set', index=idx, state='up', txqlen=5000)

    # Add inside IPv6 addresses
    logging.info('Configuring interior interface %s with address %s.',
                 db.get('interior_ifname'), db.get('dongle_rloc'))
    IP.addr('add', index=idx, address=db.get('dongle_rloc'), prefixlen=64)
    logging.info('Configuring interior interface %s with address %s.',
                 db.get('interior_ifname'), db.get('dongle_eid'))
    IP.addr('add', index=idx, address=db.get('dongle_eid'), prefixlen=64)

    # Add dongle neighbour
    IP.neigh(
        'replace',
        family=AF_INET6,
        dst=db.get('dongle_ll'),
        lladdr=db.get('dongle_mac'),
        ifindex=idx,
        nud='permanent')
    IP.neigh(
        'replace',
        family=AF_INET6,
        dst=db.get('dongle_rloc'),
        lladdr=db.get('dongle_mac'),
        ifindex=idx,
        nud='permanent')
    IP.neigh(
        'replace',
        family=AF_INET6,
        dst=db.get('dongle_eid'),
        lladdr=db.get('dongle_mac'),
        ifindex=idx,
        nud='permanent')

    # Add custom routing table
    rt_tables = _get_rt_tables()
    if not db.get('bridging_table') in rt_tables:
        _rt_add_table(db.get('bridging_table'), BR_TABLE_NR)

    # Add default route to custom table
    IP.route(
        'replace', family=AF_INET6, dst='default', table=BR_TABLE_NR, oif=idx)

    rules = IP.get_rules(family=AF_INET6)

    # Make marked packets use the custom table
    # TODO: different priorities for different dongles
    if str(db.get('bridging_mark')) not in str(rules):
        IP.rule(
            'add',
            family=AF_INET6,
            table=BR_TABLE_NR,
            priority=100,
            fwmark=int(db.get('bridging_mark')))

    # Set priority of local table lower than custom table's
    for rule in rules:
        if rule.get('table') == rt_tables.get('local'):
            IP.rule(
                'delete',
                family=AF_INET6,
                table=rule.get('table'),
                priority=rule.get_attr('FRA_PRIORITY') or 0)
    IP.rule(
        'add', family=AF_INET6, table=rt_tables.get('local'), priority=1000)

    '''
    # Rate limit traffic to the interface, 125 kbps (maximum data rate in the air)
    logging.info('Traffic rate limit established to %s on interface %s.',
                 '125 kbps', db.get('interior_ifname'))
    bash('tc qdisc add dev ' + db.get('interior_ifname') +
         ' root handle 1: cbq avpkt 1000 bandwidth 12mbit')
    bash(
        'tc class add dev ' + db.get('interior_ifname') +
        ' parent 1: classid 1:1 cbq rate 125kbit allot 1500 prio 5 bounded isolated'
    )
    bash('tc filter add dev ' + db.get('interior_ifname') +
         ' parent 1: protocol ipv6 prio 16 u32 match ip6 dst ::/0 flowid 1:1')
    '''

def _ifdown():
    # Remove custom routing table
    db.del_from_file('/etc/iproute2/rt_tables', '\n%s\t%s\n' %
                     (BR_TABLE_NR, db.get('bridging_table')), '')

    # Don't continue if the interface is already down
    idx = IP.link_lookup(ifname=db.get('interior_ifname'), operstate='UP')
    if not idx:
        return

    '''
    # Delete traffic limits
    bash('tc qdisc del dev ' + db.get('interior_ifname') +
         ' root handle 1: cbq avpkt 1000 bandwidth 12mbit')
    '''

    # Delete custom rule
    IP.rule(
        'delete',
        family=AF_INET6,
        table=BR_TABLE_NR,
        priority=100,
        fwmark=int(db.get('bridging_mark')))

    # Bring interior interface down
    logging.info('Bringing %s interface down.', db.get('interior_ifname'))
    IP.link('set', index=idx[0], state='down')


def dongle_route_enable(prefix):
    bash('ip -6 route add %s dev %s' % (prefix, db.get('interior_ifname')))


def dongle_route_disable(prefix):
    bash('ip -6 route del %s dev %s' % (prefix, db.get('interior_ifname')))


class NETWORK(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='network',
            start_keys=[
                'bridging_mark', 'bridging_table', 'interior_ifname',
                'dongle_rloc', 'interior_mac'
            ],
            start_tasks=['serial'],  # To obtain the latest dongle_rloc
            stop_tasks=['diags'],
            period=2)

    def kstart(self):
        _ifup()
        iptables.handle_ipv6('A')
        iptables.handle_diag('I')

    def kstop(self):
        iptables.handle_diag('D')
        iptables.handle_ipv6('D')
        _ifdown()

    def periodic(self):
        if not IP.link_lookup(
                ifname=db.get('interior_ifname'), operstate='UP'):
            logging.error('Interface %s went down.', db.get('interior_ifname'))
            self.kstop()
            self.kill()

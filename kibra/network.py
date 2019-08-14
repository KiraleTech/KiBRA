import hashlib
import ipaddress
import logging
import socket
import struct
import time

import kibra
import kibra.database as db
import kibra.iptables as iptables
import pyroute2  # http://docs.pyroute2.org/iproute.html#api
from kibra.ktask import Ktask
from kibra.shell import bash

DHCLIENT6_LEASES_FILE = '/var/lib/dhcp/dhclient6.leases'
BR_TABLE_NR = 200
IPR = pyroute2.IPRoute()

IFF_UP = 0x1
IFF_LOOPBACK = 0x8
IFF_MULTICAST = 0x1000


def internet_access(host='1.1.1.1', port=53, timeout=0.7):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False


def get_prefix_based_mcast(prefix, groupid):
    '''RFC 3306'''
    prefix = prefix.split('/')[0]
    prefix_bytes = ipaddress.IPv6Address(prefix).packed
    maddr_bytes = (
        bytes.fromhex('ff320040') + prefix_bytes[0:8] + struct.pack('>I', groupid)
    )
    return ipaddress.IPv6Address(maddr_bytes).compressed


def get_rloc_from_short(prefix, rloc16):
    prefix = prefix.split('/')[0]
    prefix_bytes = ipaddress.IPv6Address(prefix).packed
    rloc_bytes = prefix_bytes[0:8] + bytes.fromhex('000000fffe00' + rloc16)
    return ipaddress.IPv6Address(rloc_bytes).compressed


def global_netconfig():
    set_ext_iface()
    logging.info('External interface is %s.', db.get('exterior_ifname'))
    if not db.has_keys(['prefix']):
        logging.info('Trying to obtain a prefix via Prefix Delegation...')
        prefix = _get_prefix(db.get('exterior_ifname'))
        if not prefix:
            logging.info('It was not possible to obtain a global prefix.')
            prefix = _get_ula()
            logging.info('Generated the ULA prefix %s.' % prefix)
        # Obtain /64 subprefix
        prefix = '%s/64' % prefix.split('/')[0]
        db.set('prefix', prefix)

    # Find exterior interface addresses
    # Global IPv4 addresses
    ipv4_addrs = get_addrs(db.get('exterior_ifname'), socket.AF_INET, scope=0)
    if ipv4_addrs:
        logging.info('Using %s as exterior IPv4 address.', ipv4_addrs[0])
        db.set('exterior_ipv4', ipv4_addrs[0])

    # Link-local IPv4 addresses
    ipv4_addrs = get_addrs(db.get('exterior_ifname'), socket.AF_INET, scope=253)
    if ipv4_addrs:
        logging.info('Using %s as exterior IPv4 link-local address.', ipv4_addrs[0])
        db.set('exterior_ipv4_ll', ipv4_addrs[0])

    # Global IPv6 addresses
    ipv6_addrs = get_addrs(db.get('exterior_ifname'), socket.AF_INET6, scope=0)
    if ipv6_addrs:
        logging.info('Using %s as exterior IPv6 address.', ipv6_addrs[0])
        db.set('exterior_ipv6', ipv6_addrs[0])

    # Link-local IPv6 addresses
    ipv6_addrs = get_addrs(db.get('exterior_ifname'), socket.AF_INET6, scope=253)
    if ipv6_addrs:
        logging.info('Using %s as exterior link-local IPv6 address.', ipv6_addrs[0])
        db.set('exterior_ipv6_ll', ipv6_addrs[0])


def _get_ula():
    '''Generate a GUA as RFC4193'''
    # https://tools.ietf.org/html/rfc4193#section-3.2.2
    # Time in hexadecimal
    ntp_time = str(struct.unpack('Q', struct.pack('d', time.time()))[0])
    eui64 = get_eui64(db.get('exterior_ifnumber')).replace(':', '')
    sha = hashlib.sha256()
    sha.update((ntp_time + eui64).encode())  # SHA1 of Time + EUI64
    sha = sha.hexdigest().zfill(40)
    # fd + last 40 bits of SHA1
    ula = ipaddress.IPv6Address(int('fd' + sha[-10:] + '00000000000000000000', 16))
    return ula.compressed + '/48'


def _get_prefix(exterior_ifname):
    # TODO: Parse the leases file properly to make sure it is valid
    prefix = db.find_in_file(DHCLIENT6_LEASES_FILE, 'iaprefix ', ' {')
    if prefix:
        logging.info('Obtained global prefix %s', prefix)
        return prefix


def get_eui48(ifnumber):
    '''Get EUI48 address for the interface'''
    return IPR.link('get', index=ifnumber)[0].get_attr('IFLA_ADDRESS')


def get_eui64(ifnumber):
    eui48 = get_eui48(ifnumber)
    octets = eui48.split(':')
    return ':'.join(octets[0:3] + ['ff', 'fe'] + octets[3:6])


def add_addr(address, ifnumber):
    '''Used externally to add an address to an interface'''
    IPR.addr('add', index=ifnumber, address=address, prefixlen=64)

def get_addrs(ifname, family, scope=None):
    '''Get an address for the interface'''
    # Find configured addresses
    idx = IPR.link_lookup(ifname=ifname)[0]
    addrs = []
    try:
        for addr in IPR.get_addr(index=idx, family=family, scope=scope):
            addrs.append(addr.get_attr('IFA_ADDRESS'))
    except:
        logging.warning('Problem retrieving device addresses.')
    return addrs


def set_ext_iface():
    '''Select the right external interface'''

    if not db.get('exterior_ifname'):
        links = IPR.get_links()
        for link in links:
            # Don't choose the loopback interface
            if link['flags'] & IFF_LOOPBACK:
                continue
            # Must be up
            if not link['flags'] & IFF_UP:
                continue
            # Must have multicast enabled
            if not link['flags'] & IFF_MULTICAST:
                continue
            # Don't choose the Kirale's Thread device
            if link.get_attr('IFLA_ADDRESS').startswith('84:04:d2'):
                continue
            # First interface matching all criteria is selected
            db.set('exterior_ifname', link.get_attr('IFLA_IFNAME'))
            break

    # No appropiate interface was found
    if not db.get('exterior_ifname'):
        raise Exception('No exterior interface available.')

    # Set exterior index
    idx = IPR.link_lookup(ifname=db.get('exterior_ifname'))[0]
    db.set('exterior_ifnumber', idx)

    # Set exterior MAC
    db.set('exterior_mac', IPR.get_links(idx)[0].get_attr('IFLA_ADDRESS'))


def dongle_conf():
    '''Configure several network parameters'''
    # By Kirale convention, interior MAC address is obtained from the dongle
    # serial
    serial = db.get('dongle_serial').split('+')[-1]
    interior_mac = ':'.join(
        [
            serial[0:2],
            serial[2:4],
            serial[4:6],
            serial[10:12],
            serial[12:14],
            serial[14:16],
        ]
    )
    db.set('interior_mac', interior_mac)
    # Also dongle MAC is related to interior MAC
    dongle_mac = bytearray.fromhex(interior_mac.replace(':', ''))
    dongle_mac[0] |= 0x02
    db.set('dongle_mac', ':'.join(['%02x' % byte for byte in dongle_mac]))
    # Find the device with the configured MAC address
    links = IPR.get_links(IFLA_ADDRESS=db.get('interior_mac').lower())
    if links:
        db.set('interior_ifname', links[0].get_attr('IFLA_IFNAME'))
        db.set('interior_ifnumber', links[0]['index'])
    else:
        raise Exception('Error: Device not found with MAC ' + db.get('interior_mac'))

    # Use last 32 bits of interior MAC as bridging mark
    db.set('bridging_mark', int(db.get('interior_mac').replace(':', '')[-8:], 16))
    db.set('bridging_table', db.get('interior_mac'))
    # This is only useful when more than one interior interface is used
    # db.set('exterior_port_mc', 20000 + int(db.get('interior_mac')[-2:], 16))


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
    # For the Thread Harness, remove old neighbors
    if kibra.__harness__:
        bash('ip -6 neighbor flush all')

    # Make sure forwarding is enabled
    bash('echo 1 > /proc/sys/net/ipv4/conf/all/forwarding')
    bash('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')
    logging.info('Forwarding has been enabled.')

    # Disable duplicate address detection for the interior interface
    bash('echo 0 > /proc/sys/net/ipv6/conf/%s/accept_dad' % db.get('interior_ifname'))
    logging.info('DAD has been disabled for %s.', db.get('interior_ifname'))

    # Enable a bigger number of multicast groups
    # https://www.kernel.org/doc/Documentation/sysctl/net.txt
    bash('echo 65536 > /proc/sys/net/core/optmem_max')

    # Bring interior interface up
    idx = db.get('interior_ifnumber')
    # First bring it down to remove old invalid addresses
    IPR.link('set', index=idx, state='down')
    IPR.link('set', index=idx, state='up', txqlen=5000)

    # Add inside IPv6 addresses
    logging.info(
        'Configuring interior interface %s with address %s.',
        db.get('interior_ifname'),
        db.get('dongle_rloc'),
    )
    IPR.addr('add', index=idx, address=db.get('dongle_rloc'), prefixlen=64)
    logging.info(
        'Configuring interior interface %s with address %s.',
        db.get('interior_ifname'),
        db.get('dongle_mleid'),
    )
    IPR.addr('add', index=idx, address=db.get('dongle_mleid'), prefixlen=64)

    # Add dongle neighbour
    IPR.neigh(
        'replace',
        family=socket.AF_INET6,
        dst=db.get('dongle_ll'),
        lladdr=db.get('dongle_mac'),
        ifindex=idx,
        nud='permanent',
    )
    IPR.neigh(
        'replace',
        family=socket.AF_INET6,
        dst=db.get('dongle_rloc'),
        lladdr=db.get('dongle_mac'),
        ifindex=idx,
        nud='permanent',
    )
    IPR.neigh(
        'replace',
        family=socket.AF_INET6,
        dst=db.get('dongle_mleid'),
        lladdr=db.get('dongle_mac'),
        ifindex=idx,
        nud='permanent',
    )

    # Add custom routing table
    rt_tables = _get_rt_tables()
    if not db.get('bridging_table') in rt_tables:
        _rt_add_table(db.get('bridging_table'), BR_TABLE_NR)

    # Add default route to custom table
    IPR.route(
        'replace', family=socket.AF_INET6, dst='default', table=BR_TABLE_NR, oif=idx
    )

    rules = IPR.get_rules(family=socket.AF_INET6)

    # Make marked packets use the custom table
    # TODO: different priorities for different dongles
    if str(db.get('bridging_mark')) not in str(rules):
        IPR.rule(
            'add',
            family=socket.AF_INET6,
            table=BR_TABLE_NR,
            priority=100,
            fwmark=int(db.get('bridging_mark')),
        )

    # Set priority of local table lower than custom table's
    for rule in rules:
        if rule.get('table') == rt_tables.get('local'):
            IPR.rule(
                'delete',
                family=socket.AF_INET6,
                table=rule.get('table'),
                priority=rule.get_attr('FRA_PRIORITY') or 0,
            )
    IPR.rule('add', family=socket.AF_INET6, table=rt_tables.get('local'), priority=1000)
    # Rate limit traffic to the interface, 125 kbps (maximum data rate in the
    # air)
    logging.info(
        'Traffic rate limit established to %s on interface %s.',
        '125 kbps',
        db.get('interior_ifname'),
    )
    bash(
        'tc qdisc add dev '
        + db.get('interior_ifname')
        + ' root handle 1: cbq avpkt 1000 bandwidth 12mbit'
    )
    bash(
        'tc class add dev '
        + db.get('interior_ifname')
        + ' parent 1: classid 1:1 cbq rate 125kbit '
        + 'allot 1500 prio 5 bounded isolated'
    )
    bash(
        'tc filter add dev '
        + db.get('interior_ifname')
        + ' parent 1: protocol ipv6 prio 16 u32 match ip6 dst ::/0 flowid 1:1'
    )


def _ifdown():
    # Remove custom routing table
    db.del_from_file(
        '/etc/iproute2/rt_tables',
        '\n%s\t%s\n' % (BR_TABLE_NR, db.get('bridging_table')),
        '',
    )

    # Don't continue if the interface is already down
    idx = IPR.link_lookup(ifname=db.get('interior_ifname'), operstate='UP')
    if not idx:
        return
    '''
    # Delete traffic limits
    bash('tc qdisc del dev ' + db.get('interior_ifname') +
         ' root handle 1: cbq avpkt 1000 bandwidth 12mbit')
    '''

    # Delete custom rule
    IPR.rule(
        'delete',
        family=socket.AF_INET6,
        table=BR_TABLE_NR,
        priority=100,
        fwmark=int(db.get('bridging_mark')),
    )

    # Bring interior interface down
    logging.info('Bringing %s interface down.', db.get('interior_ifname'))
    IPR.link('set', index=db.get('interior_ifnumber'), state='down')


def dongle_route_enable(prefix):
    try:
        IPR.route(
            'replace',
            family=socket.AF_INET6,
            dst=prefix,
            oif=db.get('interior_ifnumber'),
        )
        # bash('ip -6 route add %s dev %s' % (prefix, db.get('interior_ifname')))
    except:
        logging.warning('Route for %s could not be enabled' % prefix)


def dongle_route_disable(prefix):
    try:
        IPR.route(
            'del', family=socket.AF_INET6, dst=prefix, oif=db.get('interior_ifnumber')
        )
        # bash('ip -6 route del %s dev %s' % (prefix, db.get('interior_ifname')))
    except:
        logging.warning('Route for %s could not be disabled' % prefix)


class NETWORK(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='network',
            start_keys=[
                'bridging_mark',
                'bridging_table',
                'interior_ifname',
                'dongle_rloc',
                'interior_mac',
            ],
            start_tasks=['serial'],  # To obtain the latest dongle_rloc
            stop_tasks=['diags', 'coapserver'],
            period=2,
        )

    def kstart(self):
        _ifup()
        iptables.handle_ipv6('A')
        iptables.handle_diag('I')

    def kstop(self):
        iptables.handle_diag('D')
        iptables.handle_ipv6('D')
        _ifdown()

    async def periodic(self):
        try:
            interior_link_up = IPR.link_lookup(
                ifname=db.get('interior_ifname'), operstate='UP'
            )
        except:
            interior_link_up = False
        if not interior_link_up:
            logging.error('Interface %s went down.', db.get('interior_ifname'))
            self.kstop()
            self.kill()
        # TODO: detect changes in addresses

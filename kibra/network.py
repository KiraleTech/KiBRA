import hashlib
import ipaddress
import json
import logging
import socket
import struct
import time

import kibra
import kibra.database as db
import kibra.iptables as IPTABLES
import kibra.dhcp as DHCP
import kibra.coapserver as COAPSERVER
import kibra.mdns as MDNS
import kibra.nat as NAT
import pyroute2  # http://docs.pyroute2.org/iproute.html#api
from kibra.ktask import Ktask
from kibra.shell import bash

DHCLIENT6_LEASES_FILE = '/var/lib/dhcp/dhclient6.leases'
BR_TABLE_NR = 200
IPR = pyroute2.IPRoute()

IFF_UP = 0x1
IFF_LOOPBACK = 0x8
IFF_MULTICAST = 0x1000


def send_udp(host, port, payload=''):
    '''TH: Send IPv6 UDP datagram to the exterior interface'''
    logging.info('Sending UDP: [%s]:%s %s' % (host, port, payload))
    IPPROTO_IPV6 = 41
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    iface = struct.pack('I', int(db.get('exterior_ifnumber')))
    sock.setsockopt(IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, iface)
    sock.sendto(bytes.fromhex(payload), (host, int(port)))
    sock.close()


def internet_access(host='1.1.1.1', port=53, timeout=0.7):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
        return True
    except socket.error:
        return False


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

    # Find exterior Link-local IPv6 address
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
    serial = db.get('ncp_serial').split('+')[-1]
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
    db.set('ncp_mac', ':'.join(['%02x' % byte for byte in dongle_mac]))
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
    # Use an ephemeral port valid for Jool BIB
    db.set('exterior_port_mc', 61001 + int(db.get('interior_mac')[-2:], 16))


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


def assign_addr(addr):
    '''Assign an address to the interior interface'''

    idx = db.get('interior_ifnumber')

    # Add interior interface IPv6 address
    if addr.startswith('fe80'):
        logging.info('Link-local address is %s', addr)
        db.set('ncp_ll', addr)
    else:
        try:
            IPR.addr('add', index=idx, address=addr, prefixlen=64)
        except:
            pass  # It might already exist

        # RLOC
        if 'ff:fe' in addr:
            logging.info('RLOC address is %s', addr)
            old_ncp_rloc = db.get('ncp_rloc')
            db.set('ncp_rloc', addr)

            if old_ncp_rloc and addr != old_ncp_rloc:
                # Changes in RLOC affect servers
                IPR.addr('del', index=idx, address=old_ncp_rloc, prefixlen=64)
                COAPSERVER.OLD_NCP_RLOC = old_ncp_rloc
                DHCP.dhcp_server_stop()
                DHCP.dhcp_server_start()
                IPTABLES.handle_diag('D', old_ncp_rloc)
                IPTABLES.handle_diag('I', addr)
        # ML-EID
        else:
            logging.info('ML-EID address is %s', addr)
            db.set('ncp_mleid', addr)

    # Add dongle neighbour
    IPR.neigh(
        'replace',
        family=socket.AF_INET6,
        dst=addr,
        lladdr=db.get('ncp_mac'),
        ifindex=idx,
        nud='permanent',
    )


def _ifup():
    # For the Thread Harness, remove old neighbors
    if kibra.__harness__:
        bash('ip -6 neigh flush all')

    ifname = db.get('interior_ifname')

    # Make sure forwarding is enabled
    bash('echo 1 > /proc/sys/net/ipv4/conf/all/forwarding')
    bash('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')
    logging.info('Forwarding has been enabled.')

    # Disable duplicate address detection for the interior interface
    bash('echo 0 > /proc/sys/net/ipv6/conf/%s/accept_dad' % ifname)
    logging.info('DAD has been disabled for %s.', ifname)

    # Enable a bigger number of multicast groups
    # https://www.kernel.org/doc/Documentation/sysctl/net.txt
    bash('echo 65536 > /proc/sys/net/core/optmem_max')

    # Bring interior interface up
    idx = db.get('interior_ifnumber')
    # First bring it down to remove old invalid addresses
    IPR.link('set', index=idx, state='down')
    IPR.link('set', index=idx, state='up', txqlen=5000)

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
        'Traffic rate limit established to %s on interface %s.', '125 kbps', ifname
    )
    bash('tc qdisc add dev %s root handle 1: cbq avpkt 1000 bandwidth 12mbit' % ifname)
    bash(
        'tc class add dev %s parent 1: classid 1:1 cbq rate 125kbit allot 1500 prio 5 bounded isolated'
        % ifname
    )
    bash(
        'tc filter add dev %s parent 1: protocol ipv6 prio 16 u32 match ip6 dst ::/0 flowid 1:1'
        % ifname
    )


def _ifdown():
    ifname = db.get('interior_ifname')

    # Remove custom routing table
    db.del_from_file(
        '/etc/iproute2/rt_tables',
        '\n%s\t%s\n' % (BR_TABLE_NR, db.get('bridging_table')),
        '',
    )

    # Don't continue if the interface is already down
    idx = IPR.link_lookup(ifname=ifname, operstate='UP')
    if not idx:
        return
    # Delete traffic limits
    bash('tc qdisc del dev %s root handle 1: cbq avpkt 1000 bandwidth 12mbit' % ifname)

    # Delete custom rule
    IPR.rule(
        'delete',
        family=socket.AF_INET6,
        table=BR_TABLE_NR,
        priority=100,
        fwmark=int(db.get('bridging_mark')),
    )

    # Bring interior interface down
    logging.info('Bringing %s interface down.', ifname)
    try:
        IPR.link('set', index=db.get('interior_ifnumber'), state='down')
    except:
        logging.warning('Exception bringing %s interface down.', ifname)


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
        logging.warning('Route for %s could not be enabled', prefix)


def dongle_route_disable(prefix):
    try:
        IPR.route(
            'del', family=socket.AF_INET6, dst=prefix, oif=db.get('interior_ifnumber')
        )
        # bash('ip -6 route del %s dev %s' % (prefix, db.get('interior_ifname')))
    except:
        logging.warning('Route for %s could not be disabled', prefix)


class NETWORK(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='network',
            start_keys=[],
            start_tasks=[],
            stop_tasks=['diags', 'coapserver'],
            period=1,
        )
        self.syslog = None

    def kstart(self):
        dongle_conf()
        _ifup()
        IPTABLES.handle_ipv6('A')

    def kstop(self):
        IPTABLES.handle_ipv6('D')
        _ifdown()

    async def periodic(self):
        # Detect if interior interface goes down
        try:
            IPR.link_lookup(ifname=db.get('interior_ifname'), operstate='UP')
        except:
            logging.error('Interface %s went down.', db.get('interior_ifname'))
            self.kstop()
            self.kill()

        # Don't continue if NCP RLOC has not been asigned yet
        if not db.has_keys(['ncp_rloc']):
            return

        # Keep track of exterior addresses
        iface_addrs = []
        iface_addrs += get_addrs(db.get('exterior_ifname'), socket.AF_INET)
        iface_addrs += get_addrs(db.get('exterior_ifname'), socket.AF_INET6)

        # Find which addresses to remove and which ones to add
        ext_addrs = db.get('exterior_addrs')
        old_addrs = ext_addrs
        new_addrs = []
        for addr in iface_addrs:
            if addr not in old_addrs:
                new_addrs.append(addr)
            else:
                old_addrs.remove(addr)

        # Remove old addresses
        for addr in old_addrs:
            NAT.handle_nat64_masking(addr, enable=False)
            IPTABLES.handle_bagent_fwd(addr, enable=False)

        # Add new addresses
        for addr in new_addrs:
            # TODO: except link local
            NAT.handle_nat64_masking(addr, enable=True)
            IPTABLES.handle_bagent_fwd(addr, enable=True)

        # Notify MDNS service
        if new_addrs:
            MDNS.new_external_addresses()

        db.set('exterior_addrs', iface_addrs)

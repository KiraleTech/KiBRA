'''
ND Proxy implementation
# https://tools.ietf.org/html/rfc3542
# https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/icmpv6.h
'''

import asyncio
import datetime
import ipaddress
import json
import logging
import math
import random
import socket
import struct
import time

import kibra.database as db
import kibra.network as NETWORK
from kibra.thread import DEFS

IPPROTO_IPV6 = 41
IPPROTO_ICMPV6 = 58

IPV6_UNICAST_HOPS = 16
IPV6_MULTICAST_HOPS = 18

IPV6_JOIN_GROUP = 20
IPV6_LEAVE_GROUP = 21

SOL_SOCKET = 1
SO_BINDTODEVICE = 25

# ICMPv6 filtering definitions
ICMP6_FILTER = 1

ND_NEIGHBOR_SOLICIT = 135
ND_NEIGHBOR_ADVERTISEMENT = 136

NS_FMT = '!BBHI16s'  # type, code, cksum, flags, ns_target
OPT_FMT = '!BB%ss'

EXT_IFNUMBER = None
EXT_EUI48 = None


def icmp6_filter_setpass(filter_, type_):
    index = 4 * int(type_ / 32) + 3 - int((type_ % 32) / 8)
    filter_[index] |= 1 << (type_ % 8)
    return filter_


def carry_around_add(a, b):
    c = a + b
    return (c & 0xFFFF) + (c >> 16)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s = carry_around_add(s, w)
    return ~s & 0xFFFF


class NDProxy:
    def __init__(self):
        global EXT_IFNUMBER, EXT_EUI48

        # List of PBBR DUAs with finished DAD
        self.duas = {}

        # Set exterior interface attributes
        EXT_IFNUMBER = db.get('exterior_ifnumber')
        EXT_EUI48 = bytes.fromhex(NETWORK.get_eui48(EXT_IFNUMBER).replace(':', ''))

        try:
            # Create and init the ICMPv6 socket
            self.icmp6_sock = socket.socket(
                socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMPV6
            )

            # Bind to exterior interface only
            self.icmp6_sock.setsockopt(
                SOL_SOCKET, SO_BINDTODEVICE, db.get('exterior_ifname').encode()
            )

            # Receive Neighbor Solicitation messages in this socket
            icmp6_filter = bytearray(32)  # 256 bit flags
            icmp6_filter = icmp6_filter_setpass(icmp6_filter, ND_NEIGHBOR_SOLICIT)
            self.icmp6_sock.setsockopt(IPPROTO_ICMPV6, ICMP6_FILTER, icmp6_filter)

            # Set the outgoing hop limit
            self.icmp6_sock.setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255)
            self.icmp6_sock.setsockopt(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255)

            # Run the daemon
            self.ndp_on = True
            # asyncio.ensure_future(self.run_daemon())
            asyncio.get_event_loop().run_in_executor(None, self.run_daemon)
        except:
            logging.error('Unable to create the ND Proxy socket.')

    def stop(self):
        self.ndp_on = False
        try:
            self.icmp6_sock.close()
        except:
            logging.warn('A problem occured while trying to close ND Proxy socket')

    def run_daemon(self):
        while self.ndp_on:
            # Wait for some multicast traffic to arrive
            try:
                data, src = self.icmp6_sock.recvfrom(1280)
            except:
                # socket.timeout: timed out
                time.sleep(0.2)

            # Accepting Neighbor solicit only
            if data[0] != ND_NEIGHBOR_SOLICIT:
                continue

            # Get the paramters
            _, _, _, _, tgt = struct.unpack(NS_FMT, data[: struct.calcsize(NS_FMT)])

            # Debug
            ns_tgt = ipaddress.IPv6Address(tgt).compressed
            logging.info('in ns from %s for %s' % (src[0], ns_tgt))

            # Generate Neighbor Advertisement
            if ns_tgt in db.get('exterior_addrs'):
                self.send_na(src[0], ns_tgt)
            elif ns_tgt in list(self.duas.keys()):
                delayed = not ns_tgt in db.get('ncp_eid_cache')
                self.send_na(src[0], ns_tgt, delayed=delayed)

    def add_del_dua(self, action, dua, reg_time=0, ifnumber=None):
        if not 'primary' in db.get('bbr_status'):
            return

        # RFC 4291 Solicited-Node Address for this DUA
        sn_addr_bytes = ipaddress.IPv6Address('ff02:0:0:0:0:1:ff00:0000').packed
        dua_bytes = ipaddress.IPv6Address(dua).packed
        sn_addr_bytes = ipaddress.IPv6Address(
            sn_addr_bytes[:13] + dua_bytes[13:]
        ).packed

        # Listen/Unlisten to the Solicited-Node Address
        if action == 'add':
            action_ = IPV6_JOIN_GROUP
        else:
            action_ = IPV6_LEAVE_GROUP
        if ifnumber is None:
            ifnumber = db.get('exterior_ifnumber')
        msg = struct.pack('16sI', sn_addr_bytes, ifnumber)
        try:
            self.icmp6_sock.setsockopt(IPPROTO_IPV6, action_, msg)
        except:
            # We were already listening to this address
            pass

        if action == 'add':
            # Add DUA to the list
            self.duas[dua] = reg_time

            # Establish route
            NETWORK.ncp_route_enable(dua)
        else:
            try:
                # Remove route
                NETWORK.ncp_route_disable(dua)

                # Remove DUA from the list
                self.duas.pop(dua)
            except:
                logging.warning('Unable to remove unknown DUA %s' % dua)

    def send_na(self, dst, tgt, solicited=True, delayed=False):
        R = 31
        S = 30
        O = 29
        flags = 0

        if solicited:
            flags |= 1 << S
        else:
            # Set Override flag if registration was recent
            elpsd = datetime.datetime.now().timestamp() - self.duas.get(tgt, 0)
            if elpsd < DEFS.DUA_RECENT_TIME:
                flags |= 1 << O

        # Forwarding is allways activated for this interface
        flags |= 1 << R

        # Fill header
        tgt_bytes = ipaddress.IPv6Address(tgt).packed
        header = struct.pack(NS_FMT, ND_NEIGHBOR_ADVERTISEMENT, 0, 0, flags, tgt_bytes)

        # Set Target Link-Layer Address option
        opts = struct.pack(
            OPT_FMT % len(EXT_EUI48), 2, math.ceil(len(EXT_EUI48) / 8), EXT_EUI48
        )

        # Set the checksum
        cksum = checksum(header + opts)
        header = struct.pack(
            NS_FMT, ND_NEIGHBOR_ADVERTISEMENT, 0, cksum, flags, tgt_bytes
        )

        # Apply delay if requested
        if delayed:
            delay = random.randint(64, 128) / 1000
            time.sleep(delay)

        # Send ICMPv6 packet
        try:
            self.icmp6_sock.sendto(header + opts, (dst, 0, 0, EXT_IFNUMBER))
        except Exception as exc:
            logging.warn('Cannot send NA to %s. Error: %s' % (dst, exc))

        # Logging
        logging.info('out na to %s for %s' % (dst, tgt))

'''
Multicast routing based on sockets and kernel signals
# https://www.freebsd.org/cgi/man.cgi?query=multicast&apropos=0&sektion=4
# https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/mroute6.h
# https://github.com/torvalds/linux/blob/v4.18/include/uapi/linux/in.h
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/in6.h
'''

import asyncio
import datetime
import ipaddress
import json
import logging
import socket
import struct
import time

import kibra.database as db
import kibra.iptables as iptables

MCROUTE_EXPIRY = 60

IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
IPPROTO_ICMPV6 = 58

MRT6_INIT = 200
MRT6_ADD_MIF = 202
MRT6_ADD_MFC = 204
MRT6_DEL_MFC = 205
MRT6MSG_NOCACHE = 1

IPV6_JOIN_GROUP = 20
IPV6_LEAVE_GROUP = 21

EXT_MIF = 0
INT_MIF = 1

mif6ctl_fmt = 'HBBHI'
sockaddr_in6_fmt = 'HHI16sI'
mf6cctl_fmt = '28s28sHH32s'  # Second H is padding for the non-packed struct
mrt6msg_fmt = 'BBHI16s16s'


class MCRoute:
    def __init__(self, src, dst, in_mif, out_mif):
        self.src = src
        self.dst = dst
        self.in_mif = in_mif
        self.out_mif = out_mif
        self.expiry = datetime.datetime.now().timestamp() + MCROUTE_EXPIRY

    def get_mf6cctl(self):
        src2 = struct.pack(sockaddr_in6_fmt, 0, 0, 0, self.src, 0)
        dst2 = struct.pack(sockaddr_in6_fmt, 0, 0, 0, self.dst, 0)
        ttls = bytearray(32)
        ttls[0] = 1 << self.out_mif  # Only works for MIFs 0-7
        mf6cctl = struct.pack(mf6cctl_fmt, src2, dst2, self.in_mif, 0, ttls)
        return mf6cctl

    def __str__(self):
        if self.in_mif == EXT_MIF:
            in_mif = db.get('exterior_ifname')
            out_mif = db.get('interior_ifname')
        else:
            in_mif = db.get('interior_ifname')
            out_mif = db.get('exterior_ifname')

        src = ipaddress.IPv6Address(self.src).compressed
        dst = ipaddress.IPv6Address(self.dst).compressed

        remaining = self.expiry - datetime.datetime.now().timestamp()
        if remaining < 0:
            remaining = 0

        return '(%s --> %s) Group: %s  Source: %s Remaining: %d s' % (
            in_mif,
            out_mif,
            dst,
            src,
            remaining,
        )


class MCRouter:
    def __init__(self):
        # Create and init the IPv6 Multicast Routing socket
        self.mc6r_sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMPV6)
        self.mc6r_sock.setsockopt(IPPROTO_IPV6, MRT6_INIT, 1)

        # Add multicast interfaces to the socket
        mif6ctl_ext = struct.pack(
            mif6ctl_fmt, EXT_MIF, 0, 0, db.get('exterior_ifnumber'), 0
        )
        mif6ctl_int = struct.pack(
            mif6ctl_fmt, INT_MIF, 0, 0, db.get('interior_ifnumber'), 0
        )
        self.mc6r_sock.setsockopt(IPPROTO_IPV6, MRT6_ADD_MIF, mif6ctl_ext)
        self.mc6r_sock.setsockopt(IPPROTO_IPV6, MRT6_ADD_MIF, mif6ctl_int)

        # Create the IPv6 Multicast Groups socket
        self.mc6g_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, IPPROTO_UDP)

        # Initialize the list of multicast routes
        self.mcroutes = []

        # Run the daemon
        self.mcr_on = True
        asyncio.get_event_loop().run_in_executor(None, self.run_daemon)

    def stop(self):
        self.mcr_on = False
        self.mc6r_sock.close()

    def run_daemon(self):
        while self.mcr_on:
            # Wait for some multicast traffic to arrive
            try:
                data = self.mc6r_sock.recv(1280)
            except:
                # socket.timeout: timed out
                time.sleep(0.2)

            if not 'primary' in db.get('bbr_status'):
                continue

            # Signal must start with zero
            if data[0] != 0:
                continue

            # Get the upcall paramters
            _, type_, in_mif, _, src, dst = struct.unpack(
                mrt6msg_fmt, data[: struct.calcsize(mrt6msg_fmt)]
            )

            # Debug
            src_addr = ipaddress.IPv6Address(src).compressed
            dst_addr = ipaddress.IPv6Address(dst).compressed
            logging.debug(
                'Upcall: type=%d mif=%d src=%s dst=%s'
                % (type_, in_mif, src_addr, dst_addr)
            )

            if type_ != MRT6MSG_NOCACHE:
                continue

            # Packet from Backbone Network (9.4.7.3)
            if in_mif == EXT_MIF:
                # Filter by registered multicast groups
                if not db.get('mlr_cache'):
                    continue
                maddrs = list(db.get('mlr_cache').keys())
                if str(dst_addr) not in maddrs:
                    continue
                out_mif = INT_MIF
            # Packet from Thread Network (9.4.7.4)
            elif in_mif == INT_MIF:
                # Rules 1 and 3 handled by KiNOS
                # Filter by forwarding flags
                dst_scope = dst[1] & 0x0F
                if dst_scope < 4:
                    continue
                if db.get('mcast_out_fwd') == 0:
                    continue
                if dst_scope == 4 and db.get('mcast_admin_fwd') == 0:
                    continue
                out_mif = EXT_MIF
            else:
                continue

            self.add_route(MCRoute(src, dst, in_mif, out_mif))

    def add_route(self, route):
        old_route = None

        # Remove expired routes first
        self.rem_old_routes()

        # Detect if the route already exists
        for existing_route in self.mcroutes:
            if route.get_mf6cctl() == existing_route.get_mf6cctl():
                old_route = existing_route
                break

        # If the route existed, there is no need to add it to the kernel
        if old_route:
            # Remove it because it's going to be added with updated timeout
            self.mcroutes.pop(old_route)
        else:
            self.mc6r_sock.setsockopt(IPPROTO_IPV6, MRT6_ADD_MFC, route.get_mf6cctl())

        # Save the newly created route
        self.mcroutes.append(route)

        logging.info('Route added: %s' % route)

    def rem_old_routes(self):
        now = datetime.datetime.now().timestamp()
        # TODO: optimize this
        old_routes = [x for x in self.mcroutes if x.expiry <= now]
        self.mcroutes = [x for x in self.mcroutes if x.expiry > now]

        for old_route in old_routes:
            self.mc6r_sock.setsockopt(
                IPPROTO_IPV6, MRT6_DEL_MFC, old_route.get_mf6cctl()
            )
            logging.info('Route removed: %s' % old_route)

    def rem_group_routes(self, mcgroup):
        mcgroup = ipaddress.IPv6Address(mcgroup).packed
        # TODO: optimize this
        old_routes = [
            x for x in self.mcroutes if x.dst == mcgroup and x.out_mif == INT_MIF
        ]
        self.mcroutes = [
            x for x in self.mcroutes if not (x.dst == mcgroup and x.out_mif == INT_MIF)
        ]

        for old_route in old_routes:
            self.mc6r_sock.setsockopt(
                IPPROTO_IPV6, MRT6_DEL_MFC, old_route.get_mf6cctl()
            )
            logging.info('Route removed: %s' % old_route)

    def join_leave_group(self, action, mcgroup, ifnumber=None):
        '''Join or leave a multicast group'''
        if action == 'join':
            socket_action = IPV6_JOIN_GROUP
            iptables_action = 'I'
        else:
            socket_action = IPV6_LEAVE_GROUP
            iptables_action = 'D'

        # Prevent the reception of own generated multicast
        iptables.block_local_multicast(iptables_action, mcgroup)

        # Add socket option
        mcgroup = ipaddress.IPv6Address(mcgroup).packed
        if ifnumber is None:
            ifnumber = db.get('exterior_ifnumber')
        ipv6_mreq = struct.pack('16sI', mcgroup, ifnumber)
        try:
            self.mc6g_sock.setsockopt(IPPROTO_IPV6, socket_action, ipv6_mreq)
        except Exception as exc:
            # It might be already present
            logging.warning(exc)

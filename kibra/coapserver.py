import asyncio
import datetime
import ipaddress
import json
import logging
import os
import socket
import struct
import time

import aiocoap
import aiocoap.resource as resource
import kibra
import kibra.database as db
import kibra.thread as THREAD
from aiocoap.numbers.codes import Code
from aiocoap.numbers.types import Type
from kibra.coapclient import CoapClient
from kibra.ktask import Ktask
from kibra.mcrouter import MCRouter
from kibra.ndproxy import NDProxy
from kibra.shell import bash
from kibra.thread import DEFS, TLV, URI
from kibra.tlv import ThreadTLV
from pyroute2 import IPRoute

# Global variables
IP = IPRoute()
DUA_HNDLR = None
MCAST_HNDLR = None

COAP_NO_RESPONSE = None

INFINITE_TIMESTAMP = 0

# Limit the number of DUA and Multicast registrations managed by this BBR
DUA_LIMIT = 768
MULTICAST_LIMIT = 768


class CoapServer:
    '''CoAP Server'''

    def __init__(self, addr, port, resources, iface=None):
        self.root = aiocoap.resource.Site()
        self.resources = resources
        for res in self.resources:
            self.root.add_resource(res[0], res[1])

        self.addr = addr
        self.port = port
        self.iface = iface
        self.start()

    def start(self):
        for res in self.resources:
            iface_txt = '%%%s' % self.iface if self.iface else ''
            logging.info(
                'Starting CoAP Server in [%s%s]:%s/%s'
                % (self.addr, iface_txt, self.port, '/'.join(res[0]))
            )
        self.context = aiocoap.Context()
        if self.iface:
            bind = (self.addr, self.port, 0, int(self.iface))
        else:
            bind = (self.addr, self.port)
        try:
            self.task = asyncio.Task(
                self.context.create_server_context(self.root, bind=bind)
            )
        except:
            logging.error(
                'Unable to launch CoAP server [%s%s]:%s/%s'
                % (self.addr, iface_txt, self.port, '/'.join(res[0]))
            )

    def stop(self):
        self.context.shutdown()
        if self.task:
            self.task.cancel()
            # TODO: https://github.com/chrysn/aiocoap/issues/156


class DMStatus:
    # Defined statuses
    ST_SUCESS = 0
    ST_DUA_REREGISTER = 1
    ST_INV_ADDR = 2
    ST_DUP_ADDR = 3
    ST_RES_SHRT = 4
    ST_NOT_PRI = 5
    ST_UNSPEC = 6


class DUAEntry:
    def __init__(self, src_rloc, eid, dua):
        self.src_rloc = src_rloc
        self.eid = eid
        self.dua = dua
        self.reg_time = datetime.datetime.now().timestamp()

        # Indicates DAD is in progress
        # TODO: this could be optimized by using src_rloc as DAD flag
        self.dad = True

        # Indicates that the entry should be deleted after the DAD process
        self.delete = False

    def update(self, elapsed):
        self.reg_time = datetime.datetime.now().timestamp() - elapsed


class MulticastHandler:
    def __init__(self):
        # Volatile multicast addresses list
        self.maddrs = {}

        # Start the multicast routing daemon
        self.mcrouter = MCRouter()

        # Multicast handler CoAP client
        self.coap_client = CoapClient()

        # Load presistent addresses
        self.maddr_perm_load()

    def stop(self):
        if self.coap_client is not None:
            self.coap_client.stop()
            self.coap_client = None

        self.mcrouter.stop()

    def reg_update(self, addrs, addr_tout):
        for addr in addrs:
            if addr_tout > 0:
                self.addr_add(str(addr), addr_tout)
            elif str(addr) in self.maddrs.keys():
                self.addr_remove(str(addr))
        db.set('mlr_cache', self.maddrs)

    def addr_add(self, addr, addr_tout):
        if addr_tout == 0xFFFFFFFF:
            tout = INFINITE_TIMESTAMP
            # Save the address in the presistent list
            self.addr_perm_add(addr)
        else:
            tout = datetime.datetime.now().timestamp() + addr_tout
            # Remove the address from the presistent list (if it exists)
            self.addr_perm_remove(addr)

        # Join the multicast group in the external interface for MLDv2 handling
        if addr not in self.maddrs.keys():
            self.mcrouter.join_leave_group('join', addr)

        # Save the new address in the volatile list
        self.maddrs[addr] = tout

        if addr_tout == 0xFFFFFFFF:
            how_long = 'permanently'
        else:
            how_long = '(+%d s)' % addr_tout
        logging.info('Multicast address %s registration updated %s' % (addr, how_long))

    def addr_remove(self, addr):

        # Remove the address from the volatile list
        self.maddrs.pop(addr)

        # Apply changes to cached addresses
        db.set('mlr_cache', self.maddrs)

        # Remove the address from the presistent list
        self.addr_perm_remove(addr)

        # Remove the existing multicast routes for this address
        self.mcrouter.rem_group_routes(addr)

        # Leave the multicast group
        self.mcrouter.join_leave_group('leave', addr)

        logging.info('Multicast address %s registration removed.' % addr)

    def maddr_perm_load(self):
        maddrs_perm = db.get('maddrs_perm')
        for addr in maddrs_perm:
            self.addr_add(addr, 0xFFFFFFFF)

    def addr_perm_add(self, addr):
        maddrs_perm = db.get('maddrs_perm')
        if addr not in maddrs_perm:
            maddrs_perm.append(addr)
            db.set('maddrs_perm', maddrs_perm)

    def addr_perm_remove(self, addr):
        maddrs_perm = db.get('maddrs_perm')
        if addr in maddrs_perm:
            maddrs_perm.remove(addr)
            db.set('maddrs_perm', maddrs_perm)

    def reg_periodic(self):
        now = datetime.datetime.now().timestamp()
        rem_list = [
            addr
            for addr, tout in self.maddrs.items()
            if tout != INFINITE_TIMESTAMP and tout < now
        ]
        for addr in rem_list:
            self.addr_remove(addr)


class Res_N_MR(resource.Resource):
    '''Multicast registration, Thread 1.2 5.24'''

    @staticmethod
    def parse_addrs(payload):
        # Unspecified error if bad payload
        if len(payload) % 16 != 0:
            return DMStatus.ST_UNSPEC, [], []

        status = DMStatus.ST_SUCESS
        good_addrs = []
        bad_addrs = []
        i = 0
        while i < len(payload):
            addr_bytes = bytes(payload[i : i + 16])
            # Check for valid IPv6 address
            try:
                addr = ipaddress.IPv6Address(addr_bytes)
                # Check for valid multicast address with scope > 3
                if addr.is_multicast and addr_bytes[1] & 0x0F > 3:
                    good_addrs.append(addr_bytes)
                else:
                    status = DMStatus.ST_INV_ADDR
                    bad_addrs.append(addr_bytes)
            except:
                status = DMStatus.ST_INV_ADDR
                bad_addrs.append(addr_bytes)
            i += 16
        return status, good_addrs, bad_addrs

    async def render_post(self, request):
        status = DMStatus.ST_UNSPEC
        good_addrs = []
        bad_addrs = []

        # Incoming TLVs parsing
        in_pload = ThreadTLV.sub_tlvs_str(request.payload)
        logging.info('in %s req: %s' % (URI.N_MR, in_pload))

        # Thread Harness may force response status
        mlr_next_status = db.get('mlr_next_status')
        if kibra.__harness__ and mlr_next_status:
            status = int(mlr_next_status)
            db.set('mlr_next_status', '')
            # Include bad addresses for resources shortage status
            if status == DMStatus.ST_NOT_PRI:
                # IPv6 Addresses TLV
                addrs_value = ThreadTLV.get_value(request.payload, TLV.A_IPV6_ADDRESSES)
                if addrs_value:
                    _, good, bad = Res_N_MR.parse_addrs(addrs_value)
                    bad_addrs.append(good)
                    bad_addrs.append(bad)
        # BBR Primary/Secondary status
        elif not 'primary' in db.get('bbr_status'):
            status = DMStatus.ST_NOT_PRI
        # Resources shortage
        elif len(MCAST_HNDLR.maddrs) >= MULTICAST_LIMIT:
            status = DMStatus.ST_RES_SHRT
        # Normal registration
        else:
            timeout = None
            comm_sid = None

            # IPv6 Addresses TLV
            addrs_value = ThreadTLV.get_value(request.payload, TLV.A_IPV6_ADDRESSES)
            if addrs_value:
                status, good_addrs, bad_addrs = Res_N_MR.parse_addrs(addrs_value)

            # Timeout TLV
            timeout = ThreadTLV.get_value(request.payload, TLV.A_TIMEOUT)

            # Commissioner Session ID TLV
            comm_sid = ThreadTLV.get_value(
                request.payload, TLV.A_COMMISSIONER_SESSION_ID
            )

            # Register valid addresses
            if good_addrs:
                if timeout and comm_sid:
                    addr_tout = struct.unpack('!I', timeout)[0]
                else:
                    addr_tout = db.get('mlr_timeout') or DEFS.MIN_MLR_TIMEOUT
                reg_addrs = []
                reg_addrs_bytes = []
                for addr_bytes in good_addrs:
                    reg_addrs.append(ipaddress.IPv6Address(addr_bytes).compressed)
                    reg_addrs_bytes += addr_bytes
                MCAST_HNDLR.reg_update(reg_addrs, addr_tout)

                # Send BMLR.ntf
                ipv6_addressses_tlv = ThreadTLV(
                    t=TLV.A_IPV6_ADDRESSES, l=16 * len(good_addrs), v=reg_addrs_bytes
                )
                timeout_tlv = ThreadTLV(
                    t=TLV.A_TIMEOUT, l=4, v=struct.pack('!I', addr_tout)
                )
                net_name = db.get('ncp_netname').encode()
                network_name_tlv = ThreadTLV(
                    t=TLV.A_NETWORK_NAME, l=len(net_name), v=net_name
                )
                payload = (
                    ipv6_addressses_tlv.array()
                    + timeout_tlv.array()
                    + network_name_tlv.array()
                )
                dst = '%s%%%s' % (db.get('all_network_bbrs'), db.get('exterior_ifname'))
                await MCAST_HNDLR.coap_client.non_request(
                    dst, DEFS.PORT_BB, URI.B_BMR, payload
                )

        # Fill and return the response
        out_pload = ThreadTLV(t=TLV.A_STATUS, l=1, v=[status]).array()
        addrs_payload = []
        for elem in bad_addrs:
            addrs_payload += elem
        if bad_addrs:
            out_pload += ThreadTLV(
                t=TLV.A_IPV6_ADDRESSES, l=16 * len(bad_addrs), v=bytes(addrs_payload)
            ).array()
        logging.info('out %s rsp: %s' % (URI.N_MR, ThreadTLV.sub_tlvs_str(out_pload)))
        return aiocoap.Message(code=Code.CHANGED, payload=out_pload)


class DUAHandler:
    def __init__(self):
        # DUA registrations list
        self.entries = []

        # Start the ND Proxy daemon
        self.ndproxy = NDProxy()

        # DUA handler CoAP client
        self.coap_client = CoapClient()

    def stop(self):
        self.ndproxy.stop()
        if self.coap_client is not None:
            self.coap_client.stop()
            self.coap_client = None

    def reg_update(self, src_rloc, eid, dua, elapsed):
        old_entry = None
        for entry in self.entries:
            if entry.dua == dua:
                old_entry = entry
                if entry.eid != eid:
                    logging.info(
                        'EID %s tried to register the DUA %s, already registered by EID %s',
                        eid,
                        dua,
                        entry.eid,
                    )
                    return False
        if old_entry:
            # Just update its timestamp
            old_entry.update(elapsed)
            # Keep other BBRs updated
            if not old_entry.dad:
                asyncio.ensure_future(self.announce(entry))
        else:
            # New entry
            new_entry = DUAEntry(src_rloc, eid, dua)
            self.entries.append(new_entry)
            asyncio.ensure_future(self.perform_dad(new_entry))
        logging.info('EID %s registration update for DUA %s', eid, dua)
        return True

    def find_eid(self, dua):
        for entry in self.entries:
            if dua == entry.dua:
                elapsed = datetime.datetime.now().timestamp() - entry.reg_time
                return entry.src_rloc, entry.eid, int(elapsed), entry.dad
        return None, None, None, None

    async def send_bb_query(self, client, dua, rloc16=None):
        dua_bytes = ipaddress.IPv6Address(dua).packed
        payload = ThreadTLV(t=TLV.A_TARGET_EID, l=16, v=dua_bytes).array()
        if rloc16:
            payload += ThreadTLV(t=TLV.A_RLOC16, l=2, v=rloc16).array()
        dst = '%s%%%s' % (db.get('all_domain_bbrs'), db.get('exterior_ifname'))

        logging.info('out %s qry: %s' % (URI.B_BQ, ThreadTLV.sub_tlvs_str(payload)))

        await client.non_request(dst, DEFS.PORT_BB, URI.B_BQ, payload)

    async def send_pro_bb_ntf(self, dua):
        # Find the ML-EID that registered this DUA
        _, eid, elapsed, _ = DUA_HNDLR.find_eid(dua)
        if not eid:
            return

        await self.send_ntf_msg(
            db.get('all_domain_bbrs'),
            DEFS.PORT_BB,
            URI.B_BA,
            aiocoap.NON,
            dua,
            eid,
            elapsed,
        )

    async def send_bb_ans(self, dst, dua, rloc16=None):
        # Find the ML-EID that registered this DUA
        _, eid, elapsed, dad = DUA_HNDLR.find_eid(dua)

        # Don't send if DAD is still going
        if eid is None or dad is not False:
            return

        await self.send_ntf_msg(
            dst, DEFS.PORT_BB, URI.B_BA, aiocoap.CON, dua, eid, elapsed, rloc16
        )

    async def send_addr_ntf_ans(self, dst, dua, eid, elapsed, rloc16):
        await self.send_ntf_msg(
            dst, DEFS.PORT_MM, URI.A_AN, aiocoap.CON, dua, eid, elapsed, rloc16
        )

    async def send_ntf_msg(self, dst, port, uri, mode, dua, eid, elapsed, rloc16=None):

        # Fill TLVs
        # Target EID TLV
        payload = ThreadTLV(
            t=TLV.A_TARGET_EID, l=16, v=ipaddress.IPv6Address(dua).packed
        ).array()
        # ML-EID TLV
        payload += ThreadTLV(t=TLV.A_ML_EID, l=8, v=bytes.fromhex(eid)).array()
        # RLOV16 TLV
        if rloc16:
            payload += ThreadTLV(t=TLV.A_RLOC16, l=2, v=rloc16).array()
        # Time Since Last Transaction TLV
        payload += ThreadTLV(
            t=TLV.A_TIME_SINCE_LAST_TRANSACTION, l=4, v=struct.pack('!I', elapsed)
        ).array()
        # Network Name TLV
        net_name = db.get('ncp_netname').encode()
        payload += ThreadTLV(t=TLV.A_NETWORK_NAME, l=len(net_name), v=net_name).array()
        logging.info('out %s ans: %s' % (uri, ThreadTLV.sub_tlvs_str(payload)))

        if mode == aiocoap.CON:
            await self.coap_client.con_request(dst, port, uri, payload)
        else:
            await self.coap_client.non_request(dst, port, uri, payload)

    async def send_addr_err(self, dst, mtype, dua, eid_iid):
        'Thread 1.2 5.23.3.6.4'
        dua_bytes = ipaddress.IPv6Address(dua).packed
        payload = ThreadTLV(t=TLV.A_TARGET_EID, l=16, v=dua_bytes).array()
        payload += ThreadTLV(t=TLV.A_ML_EID, l=8, v=bytes.fromhex(eid_iid)).array()

        logging.info('out %s ntf: %s' % (URI.A_AE, ThreadTLV.sub_tlvs_str(payload)))

        await self.coap_client.request(dst, DEFS.PORT_MM, URI.A_AE, mtype, payload)

    async def perform_dad(self, entry):
        # Send BB.qry DUA_DAD_REPEAT times
        for _ in range(DEFS.DUA_DAD_REPEAT):
            await self.send_bb_query(self.coap_client, entry.dua)
            await asyncio.sleep(DEFS.DUA_DAD_QUERY_TIMEOUT)

            # Finsih process if duplication was detected meanwhile
            if not entry.dad:
                break

        # Set DAD flag as finished
        entry.dad = False

        if entry.delete:
            logging.info('DUA %s was duplicated, removing...' % entry.dua)
            self.remove_entry(entry)
        else:
            # Announce successful registration to other BBRs
            await self.announce(entry)

    def duplicated_found(self, dua, delete=False):
        '''
        Change the DAD flag for this entry, so that the ongoing DAD process
        removes it
        '''
        for entry in self.entries:
            if dua == entry.dua:
                entry.dad = False
                entry.delete = delete

    async def announce(self, entry):
        '''9.4.8.2.3 DUA Registration Notifications'''

        # Add ND Proxy neighbor
        self.ndproxy.add_del_dua('add', entry.dua, entry.reg_time)

        # Send PRO_BB.ntf (9.4.8.4.4)
        await DUA_HNDLR.send_pro_bb_ntf(entry.dua)

        # Send unsolicited NA
        if kibra.__harness__:
            nd_na_repeats = DEFS.MAX_NEIGHBOR_ADVERTISEMENT
        else:
            nd_na_repeats = DEFS.CFG_NEIGHBOR_ADVERTISEMENT
        for _ in range(nd_na_repeats):
            self.ndproxy.send_na('ff02::1', entry.dua, solicited=False)
            await asyncio.sleep(DEFS.RETRANS_TIMER)

        # Send repetition of PRO_BB.ntf
        if kibra.__harness__:
            await asyncio.sleep(3)
            await DUA_HNDLR.send_pro_bb_ntf(entry.dua)

    def remove_entry(self, entry=None, dua=None):
        if not entry:
            for entry_ in self.entries:
                if dua == entry_.dua:
                    entry = entry_
        if not entry:
            return
        logging.info('DUA %s with EID %s has been removed' % (entry.dua, entry.eid))
        self.ndproxy.add_del_dua('del', entry.dua)
        self.entries.remove(entry)


class Res_N_DR(resource.Resource):
    '''DUA registration, Thread 1.2 5.23'''

    async def render_post(self, request):
        req_dua = None
        status = DMStatus.ST_UNSPEC

        # Incoming TLVs parsing
        logging.info(
            'in %s req: %s' % (URI.N_DR, ThreadTLV.sub_tlvs_str(request.payload))
        )

        # BBR Primary/Secondary status
        if not 'primary' in db.get('bbr_status'):
            status = DMStatus.ST_NOT_PRI
        elif len(DUA_HNDLR.entries) >= DUA_LIMIT:
            status = DMStatus.ST_RES_SHRT
        else:
            dua = None
            eid = None
            elapsed = 0
            # Only used for sending ADDR_ERR.ntf in case of DAD finds duplicate
            src_rloc = request.remote.sockaddr[0]

            # ML-EID TLV
            value = ThreadTLV.get_value(request.payload, TLV.A_ML_EID)
            if value:
                eid = value.hex()

            # Target EID TLV
            value = ThreadTLV.get_value(request.payload, TLV.A_TARGET_EID)
            if value:
                try:
                    req_dua = bytes(value)
                    dua = ipaddress.IPv6Address(req_dua).compressed
                except:
                    status = DMStatus.ST_INV_ADDR

            # Time Since Last Transaction TLV
            value = ThreadTLV.get_value(
                request.payload, TLV.A_TIME_SINCE_LAST_TRANSACTION
            )
            if value:
                elapsed = struct.unpack('!I', value)[0]

            if eid and dua:
                # Thread Harness may force response status
                if kibra.__harness__ and eid == db.get('dua_next_status_eid'):
                    status = int(db.get('dua_next_status'))
                    db.set('dua_next_status_eid', '')
                    db.set('dua_next_status', '')
                    # DUA-TC-17 step 48
                    if status == 500:
                        return aiocoap.Message(code=Code.INTERNAL_SERVER_ERROR)
                elif DUA_HNDLR.reg_update(src_rloc, eid, dua, elapsed):
                    status = DMStatus.ST_SUCESS
                else:
                    # Duplication detected
                    status = DMStatus.ST_DUP_ADDR

        # Fill and return the response
        payload = ThreadTLV(t=TLV.A_STATUS, l=1, v=[status]).array()
        if req_dua:
            payload += ThreadTLV(t=TLV.A_TARGET_EID, l=16, v=req_dua).array()
        logging.info('out %s rsp: %s' % (URI.N_DR, ThreadTLV.sub_tlvs_str(payload)))
        return aiocoap.Message(code=Code.CHANGED, payload=payload)


class Res_B_BMR(resource.Resource):
    '''Backbone Multicast Listener Report Notification, Thread 1.2 9.4.8.4.5'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s ntf: %s' % (URI.B_BMR, ThreadTLV.sub_tlvs_str(request.payload))
        )

        # Primary BBR shouldn't receive this message
        if not 'secondary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE

        '''
        # IPv6 Addresses TLV
        addrs = []
        value = ThreadTLV.get_value(request.payload, TLV.A_IPV6_ADDRESSES)
        if value:
            _, addrs, _ = Res_N_MR.parse_addrs(value)

        # Timeout TLV
        timeout = ThreadTLV.get_value(request.payload, TLV.A_TIMEOUT)

        # Register valid addresses
        if addrs and timeout:
            MCAST_HNDLR.reg_update(addrs, timeout)
        '''
        # TODO: mantain a Backup Multicast Listeners Table

        return COAP_NO_RESPONSE


class Res_B_BQ(resource.Resource):
    '''Backbone Query, Thread 1.2 9.4.8.4.2'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s qry: %s' % (URI.B_BQ, ThreadTLV.sub_tlvs_str(request.payload))
        )

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE

        dua = None
        value = ThreadTLV.get_value(request.payload, TLV.A_TARGET_EID)
        if value:
            dua = ipaddress.IPv6Address(bytes(value)).compressed
        rloc16 = ThreadTLV.get_value(request.payload, TLV.A_RLOC16)

        if not dua:
            return COAP_NO_RESPONSE

        # Send BB.ans to the requester
        src_addr = request.remote.sockaddr[0]
        await DUA_HNDLR.send_bb_ans(src_addr, dua, rloc16=rloc16)

        return COAP_NO_RESPONSE


def _get_b_ba_params(payload):
    '''Extract paramters from a BB.ans or PRO_BB.ntf payload'''
    dua = None
    eid = None
    rloc16 = None
    elapsed = None
    net_name = None
    value = ThreadTLV.get_value(payload, TLV.A_TARGET_EID)
    if value:
        dua = ipaddress.IPv6Address(bytes(value)).compressed
        value = ThreadTLV.get_value(payload, TLV.A_ML_EID)
    if value:
        eid = value.hex()
    value = ThreadTLV.get_value(payload, TLV.A_RLOC16)

    if value:
        rloc16 = value.hex()
    value = ThreadTLV.get_value(payload, TLV.A_TIME_SINCE_LAST_TRANSACTION)
    if value:
        elapsed = struct.unpack('!I', value)[0]
    value = ThreadTLV.get_value(payload, TLV.A_NETWORK_NAME)
    if value:
        net_name = struct.unpack('%ds' % len(value), value)[0].decode()

    return dua, eid, rloc16, elapsed, net_name


class Res_B_BA_uni(resource.Resource):
    '''Backbone Answer, Thread 1.2 9.4.8.4.3'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s ans: %s' % (URI.B_BA, ThreadTLV.sub_tlvs_str(request.payload))
        )

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE
            # TODO: 9.4.8.2.9 Caching DUAs Advertised on the Backbone Link

        # Check if all required TLVs are present
        dua, eid, rloc16, elapsed, net_name = _get_b_ba_params(request.payload)
        if None in (dua, eid, elapsed, net_name):
            return COAP_NO_RESPONSE

        logging.info(
            'BB.ans: DUA=%s, ML-EID=%s, Time=%d, Net Name=%s, RLOC16=%s'
            % (dua, eid, elapsed, net_name, rloc16)
        )

        # See if we have this DUA in our table
        src_rloc, entry_eid, _, dad = DUA_HNDLR.find_eid(dua)

        # 9.4.8.2.8 Receipt of Backbone Answer BB.ans
        if not rloc16:
            if not entry_eid:
                # Nothing to do for this EID
                return COAP_NO_RESPONSE
            elif dad is True:
                if entry_eid == eid:
                    # This DUA is still registered somewhere else, inform others
                    DUA_HNDLR.duplicated_found(dua, delete=False)
                    # Send PRO_BB.ntf
                    asyncio.ensure_future(DUA_HNDLR.send_pro_bb_ntf(dua))
                else:
                    # Duplication detected during DAD
                    DUA_HNDLR.duplicated_found(dua, delete=True)
                    # Send ADDR_ERR.ntf
                    asyncio.ensure_future(
                        DUA_HNDLR.send_addr_err(src_rloc, aiocoap.CON, dua, eid)
                    )

        else:
            # Send ADDR_NTF.ans
            bbr_rloc16 = ipaddress.IPv6Address(db.get('ncp_rloc')).packed[-2:]
            # If this BBR NCP originated the addr_qry, send addr_ntf to its
            # link local address
            if rloc16 == bbr_rloc16:
                dst = db.get('ncp_ll')
            else:
                dst = THREAD.get_rloc_from_short(db.get('ncp_prefix'), rloc16)
            asyncio.ensure_future(
                DUA_HNDLR.send_addr_ntf_ans(
                    dst, dua, eid=eid, rloc16=bbr_rloc16, elapsed=elapsed
                )
            )

        # ACK
        return aiocoap.Message(mtype=Type.ACK, code=Code.CHANGED)


class Res_B_BA_multi(resource.Resource):
    '''Proactive Backbone Notification, Thread 1.2 9.4.8.2.4'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s ans: %s' % (URI.B_BA, ThreadTLV.sub_tlvs_str(request.payload))
        )

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE
            # TODO: 9.4.8.2.9 Caching DUAs Advertised on the Backbone Link

        # Check if all required TLVs are present
        dua, eid, _, elapsed, net_name = _get_b_ba_params(request.payload)
        if None in (dua, eid, elapsed, net_name):
            return COAP_NO_RESPONSE

        logging.info(
            'PRO_BB.ntf: DUA=%s, ML-EID=%s, Time=%d, Net Name=%s'
            % (dua, eid, elapsed, net_name)
        )

        # Se if we have this DUA in our table
        _, entry_eid, entry_elapsed, _ = DUA_HNDLR.find_eid(dua)

        # 9.4.8.2.4 Receipt of Proactive Backbone Notification PRO_BB.ntf Multicast
        if not entry_eid:
            # TODO: 9.4.8.2.9 Caching DUAs Advertised on the Backbone Link
            return COAP_NO_RESPONSE
        elif entry_eid == eid:
            # Case 1: ML-EID IID matches
            if entry_elapsed < elapsed:
                # Send PRO_BB.ntf
                asyncio.ensure_future(DUA_HNDLR.send_pro_bb_ntf(dua))
            else:
                # This DUA has been registered somewhere else more recently
                # Remove silently
                DUA_HNDLR.remove_entry(dua=dua)
        else:
            # Case 2: ML-EID IID does not match (that is, duplicate address detected)
            DUA_HNDLR.remove_entry(dua=dua)
            # Send ADDR_ERR.ntf
            # Special KiBRA-KiNOS message that triggers a multicast ADDR_ERR.ntf
            asyncio.ensure_future(
                DUA_HNDLR.send_addr_err(db.get('ncp_rloc'), aiocoap.NON, dua, eid)
            )

        # No ACK
        return COAP_NO_RESPONSE


class Res_A_AQ(resource.Resource):
    '''Address Query, Thread 1.2 9.4.8.2.6'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s qry: %s' % (URI.A_AQ, ThreadTLV.sub_tlvs_str(request.payload))
        )

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE

        # Find sub TLVs
        dua = None
        value = ThreadTLV.get_value(request.payload, TLV.A_TARGET_EID)
        if value:
            dua = ipaddress.IPv6Address(bytes(value))
        if not dua:
            return COAP_NO_RESPONSE

        # Don't process requests for different prefixes than DUA
        dua_prefix = ipaddress.IPv6Address(db.get('prefix').split('/')[0])
        if dua.packed[:8] != dua_prefix.packed[:8]:
            return COAP_NO_RESPONSE

        # Obtain the RLOC16 from the source's RLOC
        rloc16 = ipaddress.IPv6Address(request.remote.sockaddr[0]).packed[-2:]

        # TODO: mantain a cache
        # Propagate Address Query to the Backbone
        await DUA_HNDLR.send_bb_query(DUA_HNDLR.coap_client, dua, rloc16)

        return COAP_NO_RESPONSE


class Res_A_AE(resource.Resource):
    '''Address Error, Thread 1.2 5.23.3.9'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s ntf: %s' % (URI.A_AE, ThreadTLV.sub_tlvs_str(request.payload))
        )

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE

        # Find sub TLVs
        dua = None
        eid = None
        value = ThreadTLV.get_value(request.payload, TLV.A_TARGET_EID)
        if value:
            dua = ipaddress.IPv6Address(bytes(value))
        value = ThreadTLV.get_value(request.payload, TLV.A_ML_EID)
        if value:
            eid = value.hex()
        if not dua or not eid:
            return COAP_NO_RESPONSE

        # Don't process notifications for different prefixes than DUA
        dua_prefix = ipaddress.IPv6Address(db.get('prefix').split('/')[0])
        if dua.packed[:8] != dua_prefix.packed[:8]:
            return COAP_NO_RESPONSE

        # Remove entry if it's registered with different EID
        _, entry_eid, _, dad = DUA_HNDLR.find_eid(dua.compressed)
        if not dad and entry_eid != eid:
            DUA_HNDLR.remove_entry(dua=dua)

        return COAP_NO_RESPONSE


class COAPSERVER(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='coapserver',
            start_keys=['prefix_dua', 'ncp_rloc', 'ncp_prefix'],
            stop_keys=['all_network_bbrs'],
            start_tasks=['serial', 'network', 'syslog'],
            stop_tasks=[],
            period=1,
        )

        # Initialize resources
        REG_RES = [(URI.tuple(URI.N_MR), Res_N_MR()), (URI.tuple(URI.N_DR), Res_N_DR())]
        RLOC_RES = REG_RES + [(URI.tuple(URI.A_AE), Res_A_AE())]

        # addr_name: [iface, port, resources]
        self.required_coap_servers = {
            'ncp_rloc': ['interior_ifnumber', DEFS.PORT_MM, RLOC_RES],
            'interior_ipv6_ll': ['interior_ifnumber', DEFS.PORT_MM, RLOC_RES],
            'bbr_primary_aloc': ['interior_ifnumber', DEFS.PORT_MM, REG_RES],
            'bbr_service_aloc': ['interior_ifnumber', DEFS.PORT_MM, REG_RES],
            'all_network_bbrs': [
                'exterior_ifnumber',
                db.get('bbr_port'),
                [(URI.tuple(URI.B_BMR), Res_B_BMR())],
            ],
            'realm_local_all_routers': [
                'interior_ifnumber',
                DEFS.PORT_MM,
                [(URI.tuple(URI.A_AQ), Res_A_AQ()), (URI.tuple(URI.A_AE), Res_A_AE())],
            ],
            'all_domain_bbrs': [
                'exterior_ifnumber',
                db.get('bbr_port'),
                [
                    (URI.tuple(URI.B_BQ), Res_B_BQ()),
                    (URI.tuple(URI.B_BA), Res_B_BA_multi()),
                ],
            ],
            'exterior_ipv6_ll': [
                'interior_ifnumber',
                db.get('bbr_port'),
                [(URI.tuple(URI.B_BA), Res_B_BA_uni())],
            ],
        }

        # addr_name: [iface, description]
        self.mcast_groups = {
            'realm_local_all_routers': ['interior_ifnumber', 'Realm-Local All-Routers'],
            'all_network_bbrs': ['exterior_ifnumber', 'All Network BBRs'],
            'all_domain_bbrs': ['exterior_ifnumber', ' All Domain BBRs'],
        }

        # Restore possible set values
        db.set('bbr_primary_aloc', None)
        db.set('bbr_service_aloc', None)

    def kstart(self):
        global DUA_HNDLR
        global MCAST_HNDLR

        self.last_ncp_rloc = None
        self.last_bbr_status = 'off'

        logging.info('Starting DUA handler')
        DUA_HNDLR = DUAHandler()
        logging.info('Starting Multicast handler')
        MCAST_HNDLR = MulticastHandler()

        # Set All Network BBRs multicast address as per 9.4.8.1
        db.set(
            'all_network_bbrs', THREAD.get_prefix_based_mcast(db.get('ncp_prefix'), 3)
        )

        # Set All Domain BBRs multicast address as per 9.4.8.1
        db.set('all_domain_bbrs', THREAD.get_prefix_based_mcast(db.get('prefix'), 3))

        # Listen for CoAP in required multicast addresses
        for group, params in self.mcast_groups.items():
            logging.info('Joining %s group: %s' % (params[1], db.get(group)))
            MCAST_HNDLR.mcrouter.join_leave_group(
                'join', db.get(group), db.get(params[0])
            )

        # CoAP servers
        self.running_coap_servers = []
        self._launch_servers()

    def kstop(self):
        logging.info('Stopping CoAP servers')
        for coap_server in self.running_coap_servers:
            coap_server.stop()

        db.set('bbr_status', 'off')

        # Un-listen for CoAP in required multicast addresses
        for group, params in self.mcast_groups.items():
            logging.info('Leaving %s group: %s' % (params[1], db.get(group)))
            MCAST_HNDLR.mcrouter.join_leave_group(
                'leave', db.get(group), db.get(params[0])
            )

        logging.info('Stopping Multicast handler')
        MCAST_HNDLR.stop()
        logging.info('Stopping DUA handler')
        DUA_HNDLR.stop()

    async def periodic(self):

        MCAST_HNDLR.reg_periodic()

        # Keept track of RLOC changes
        current_ncp_rloc = db.get('ncp_rloc')
        if current_ncp_rloc != self.last_ncp_rloc:
            self._ncp_rloc_changed(self.last_ncp_rloc)
            self.last_ncp_rloc = current_ncp_rloc

        # Keep track of BBR status changes
        current_bbr_status = db.get('bbr_status')
        if current_bbr_status != self.last_bbr_status:
            if current_bbr_status == 'primary':
                self._launch_servers()
            self.last_bbr_status = current_bbr_status

    def _launch_servers(self):
        # Find running servers
        running_addrs = []
        for coap_server in self.running_coap_servers:
            running_addrs.append(coap_server.addr)

        # Add missing servers
        for addr_name, params in self.required_coap_servers.items():
            addr = db.get(addr_name)
            if addr and addr not in running_addrs:
                self.running_coap_servers.append(
                    CoapServer(
                        addr=addr,
                        port=params[1],
                        resources=params[2],
                        iface=db.get(params[0]),
                    )
                )

    def _ncp_rloc_changed(self, old_ncp_rloc):
        for coap_server in self.running_coap_servers:
            if coap_server.addr == old_ncp_rloc:
                logging.info('A change in NCP RLOC triggered a CoAP server reload.')
                coap_server.context.shutdown()
                coap_server.addr = db.get('ncp_rloc')
                coap_server.start()

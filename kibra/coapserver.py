import asyncio
import datetime
import ipaddress
import logging
import os
import socket
import struct
import time

import aiocoap
import aiocoap.resource as resource
import kibra.database as db
import kibra.ksh as KSH
import kibra.network as NETWORK
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

#COAP_NO_RESPONSE = aiocoap.message.Message(no_response=26)
COAP_NO_RESPONSE = None

# Use a single CoAP client for the Backbone notifications
COAP_CLIENT = CoapClient()


class CoapServer():
    '''CoAP Server'''

    def __init__(self, addr, port, resources):
        root = aiocoap.resource.Site()
        for res in resources:
            root.add_resource(res[0], res[1])
        self.task = asyncio.Task(
            aiocoap.Context.create_server_context(root, bind=(addr, port)))

    def stop(self):
        self.task.cancel()


class DMStatus():
    # Defined statuses
    ST_SUCESS = 0
    ST_INV_ADDR = 2
    ST_DUP_ADDR = 3
    ST_RES_SHRT = 4
    ST_NOT_PRI = 5
    ST_UNSPEC = 6


class DUAEntry():
    def __init__(self, eid, dua):
        self.eid = eid
        self.dua = dua
        self.reg_time = datetime.datetime.now().timestamp()

        # Indicates DAD is in progress
        self.dad = True

    def update(self, elapsed):
        self.reg_time = datetime.datetime.now().timestamp() - elapsed


class MulticastHandler():
    def __init__(self):
        # Volatile multicast addresses list
        self.maddrs = {}

        # Load presistent addresses
        maddrs_perm = db.get('maddrs_perm') or []
        for addr in maddrs_perm:
            self.addr_add(addr, datetime.datetime.max)

        # Start the multicast routing daemon
        self.mcrouter = MCRouter()

    def stop(self):
        self.mcrouter.stop()

    def reg_update(self, addrs, addr_tout):
        for addr in addrs:
            if addr_tout > 0:
                self.addr_add(str(addr), addr_tout)
            elif str(addr) in self.maddrs.keys():
                self.addr_remove(str(addr))
        db.set('mlr_cache', str(self.maddrs))

    def addr_add(self, addr, addr_tout):
        if addr_tout == 0xffffffff:
            tout = datetime.datetime.max
            # Save the address in the presistent list
            maddrs_perm = db.get('maddrs_perm') or []
            if addr not in maddrs_perm:
                maddrs_perm.append(addr)
                db.set('maddrs_perm', maddrs_perm)
        else:
            if addr_tout < DEFS.MIN_MLR_TIMEOUT:
                addr_tout = DEFS.MIN_MLR_TIMEOUT
            tout = datetime.datetime.now().timestamp() + addr_tout

        # Join the multicast group in the external interface for MLDv2 handling
        if addr not in self.maddrs.keys():
            self.mcrouter.join_leave_group('join', addr)

        # Save the new address in the volatile list
        self.maddrs[addr] = tout

        logging.info('Multicast address %s registration updated (+%d s)' %
                     (addr, addr_tout))

    def addr_remove(self, addr):

        # Remove the address from the volatile list
        self.maddrs.pop(addr)

        # Apply changes to cached addresses
        db.set('mlr_cache', str(self.maddrs))

        # Remove the address from the presistent list
        maddrs_perm = db.get('maddrs_perm') or []
        if addr in maddrs_perm:
            maddrs_perm.pop(addr)
            db.set('maddrs_perm', maddrs_perm)

        # Remove the existing multicast routes for this address
        self.mcrouter.rem_group_routes(addr)

        # Leave the multicast group
        self.mcrouter.join_leave_group('leave', addr)

        logging.info('Multicast address %s registration removed.' % addr)

    def reg_periodic(self):
        now = datetime.datetime.now().timestamp()
        rem_list = [addr for addr, tout in self.maddrs.items() if tout < now]
        for addr in rem_list:
            self.addr_remove(addr)


class Res_N_MR(resource.Resource):
    '''Multicast registration, Thread 1.2 5.24'''

    @staticmethod
    def _parse_addrs(payload):
        # Unspecified error if bad payload
        if len(payload) % 16 != 0:
            return DMStatus.ST_UNSPEC, [], []

        status = DMStatus.ST_SUCESS
        good_addrs = []
        bad_addrs = []
        i = 0
        while i < len(payload):
            addr_bytes = bytes(payload[i:i + 16])
            # Check for valid IPv6 address
            try:
                addr = ipaddress.IPv6Address(addr_bytes)
                # Check for valid multicast address with scope > 3
                if addr.is_multicast and payload[i + 1] & 0x0F > 3:
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

        # BBR Primary/Secondary status
        if 'primary' not in db.get('bbr_status'):
            status = DMStatus.ST_NOT_PRI
        else:
            timeout = None
            comm_sid = None

            # IPv6 Addresses TLV
            addrs_value = ThreadTLV.get_value(request.payload,
                                              TLV.A_IPV6_ADDRESSES)
            if addrs_value:
                status, good_addrs, bad_addrs = Res_N_MR._parse_addrs(
                    addrs_value)

            # Timeout TLV
            timeout = ThreadTLV.get_value(request.payload, TLV.A_TIMEOUT)

            # Commissioner Session ID TLV
            comm_sid = ThreadTLV.get_value(request.payload,
                                           TLV.A_COMMISSIONER_SESSION_ID)

            # Register valid addresses
            if good_addrs:
                if timeout and comm_sid:
                    addr_tout = timeout
                else:
                    addr_tout = db.get('mlr_timeout') or DEFS.MIN_MLR_TIMEOUT
                reg_addrs = []
                reg_addrs_bytes = []
                for addr_bytes in good_addrs:
                    reg_addrs.append(
                        ipaddress.IPv6Address(addr_bytes).compressed)
                    reg_addrs_bytes += addr_bytes
                MCAST_HNDLR.reg_update(reg_addrs, addr_tout)
                # Send BMLR.ntf
                ipv6_addressses_tlv = ThreadTLV(
                    t=TLV.A_IPV6_ADDRESSES,
                    l=16 * len(good_addrs),
                    v=reg_addrs_bytes)
                timeout_tlv = ThreadTLV(
                    t=TLV.A_TIMEOUT, l=4, v=struct.pack('!I', addr_tout))
                payload = ipv6_addressses_tlv.array() + timeout_tlv.array()
                dst = '%s%%%s' % (db.get('all_network_bbrs'),
                                  db.get('exterior_ifname'))
                await COAP_CLIENT.non_request(dst, DEFS.PORT_BB, URI.B_BMR,
                                              payload)

        # Fill and return the response
        out_pload = ThreadTLV(t=TLV.A_STATUS, l=1, v=[status]).array()
        addrs_payload = []
        for elem in bad_addrs:
            addrs_payload += elem
        if bad_addrs:
            out_pload += ThreadTLV(
                t=TLV.A_IPV6_ADDRESSES,
                l=16 * len(bad_addrs),
                v=bytes(addrs_payload)).array()
        logging.info(
            'out %s rsp: %s' % (URI.N_MR, ThreadTLV.sub_tlvs_str(out_pload)))
        return aiocoap.Message(code=Code.CHANGED, payload=out_pload)


class DUAHandler():
    def __init__(self):
        # DUA registrations list
        self.entries = []

        # Start the ND Proxy daemon
        self.ndproxy = NDProxy()

    def stop(self):
        self.ndproxy.stop()

    def reg_update(self, eid, dua, elapsed):
        old_entry = None
        for entry in self.entries:
            if entry.dua == dua:
                old_entry = entry
                if entry.eid != eid:
                    logging.info(
                        'EID %s tried to register the DUA %s, already registered by EID %s',
                        eid, dua, entry.eid)
                    return False
        if old_entry:
            # Just update its timestamp
            old_entry.update(elapsed)
            # Keep other BBRs updated
            self.announce(entry)
        else:
            # New entry
            new_entry = DUAEntry(eid, dua)
            self.entries.append(new_entry)
            asyncio.ensure_future(self.perform_dad(new_entry))
        logging.info('EID %s registration update for DUA %s', eid, dua)
        return True

    def find_eid(self, dua):
        for entry in self.entries:
            if dua == entry.dua:
                elapsed = datetime.datetime.now().timestamp() - entry.reg_time
                return entry.eid, int(elapsed), entry.dad
        return None, None, None

    async def send_bb_query(self, dua, rloc16=None):
        dua_bytes = ipaddress.IPv6Address(dua).packed
        payload = ThreadTLV(t=TLV.A_TARGET_EID, l=16, v=dua_bytes).array()
        if rloc16:
            payload += ThreadTLV(t=TLV.A_RLOC16, l=2, v=rloc16).array()
        dst = '%s%%%s' % (db.get('all_domain_bbrs'), db.get('exterior_ifname'))

        logging.info(
            'out %s qry: %s' % (URI.B_BQ, ThreadTLV.sub_tlvs_str(payload)))

        client = CoapClient()
        await client.non_request(dst, DEFS.PORT_BB, URI.B_BQ, payload)
        client.stop()
        del client

    async def send_pro_bb_ntf(self, dua):
        await self.send_ntf_msg(
            db.get('all_domain_bbrs'), DEFS.PORT_BB, URI.B_BA, aiocoap.NON,
            dua)

    async def send_bb_ans(self, dst, dua, rloc16=None):
        await self.send_ntf_msg(
            dst, DEFS.PORT_BB, URI.B_BA, aiocoap.CON, dua, rloc16=rloc16)

    async def send_addr_ntf_ans(self, dst, dua, eid, rloc16, elapsed):
        await self.send_ntf_msg(
            dst,
            DEFS.PORT_MM,
            URI.A_AN,
            aiocoap.CON,
            dua,
            eid=eid,
            rloc16=rloc16,
            elapsed=elapsed)

    async def send_ntf_msg(self,
                           dst,
                           port,
                           uri,
                           mode,
                           dua,
                           eid=None,
                           rloc16=None,
                           elapsed=None):
        if eid is None:
            # Find the ML-EID that registered this DUA
            eid, elapsed, dad = DUA_HNDLR.find_eid(dua)

            # Don't send if DAD is still going
            if eid is None or dad is not False:
                return

        # Fill TLVs
        # Target EID TLV
        payload = ThreadTLV(
            t=TLV.A_TARGET_EID, l=16,
            v=ipaddress.IPv6Address(dua).packed).array()
        # ML-EID TLV
        payload += ThreadTLV(t=TLV.A_ML_EID, l=8, v=bytes.fromhex(eid)).array()
        # RLOV16 TLV
        if rloc16:
            payload += ThreadTLV(t=TLV.A_RLOC16, l=2, v=rloc16).array()
        # Time Since Last Transaction TLV
        payload += ThreadTLV(
            t=TLV.A_TIME_SINCE_LAST_TRANSACTION,
            l=4,
            v=struct.pack('!I', elapsed)).array()
        # Network Name TLV
        net_name = db.get('dongle_netname').encode()
        payload += ThreadTLV(
            t=TLV.A_NETWORK_NAME, l=len(net_name), v=net_name).array()

        logging.info('out %s ans: %s' % (uri, ThreadTLV.sub_tlvs_str(payload)))
        if mode == aiocoap.CON:
            await COAP_CLIENT.con_request(dst, port, uri, payload)
        else:
            await COAP_CLIENT.non_request(dst, port, uri, payload)

    async def send_addr_err(self, dua, eid_iid, dst_iid):
        'Thread 1.2 5.23.3.6.4'
        dua_bytes = ipaddress.IPv6Address(dua).packed
        payload = ThreadTLV(t=TLV.A_TARGET_EID, l=16, v=dua_bytes).array()
        payload += ThreadTLV(
            t=TLV.A_ML_EID, l=8, v=bytes.fromhex(eid_iid)).array()

        prefix_bytes = ipaddress.IPv6Address(
            db.get('dongle_prefix').split('/')[0]).packed
        dst = ipaddress.IPv6Address(prefix_bytes[0:8] + bytes.fromhex(dst_iid))

        logging.info(
            'out %s ntf: %s' % (URI.A_AE, ThreadTLV.sub_tlvs_str(payload)))

        await COAP_CLIENT.con_request(dst.compressed, DEFS.PORT_MM, URI.A_AE,
                                      payload)

    async def perform_dad(self, entry):
        # Send BB.qry DUA_DAD_REPEAT times
        for _ in range(DEFS.DUA_DAD_REPEAT):
            await self.send_bb_query(entry.dua)
            await asyncio.sleep(DEFS.DUA_DAD_QUERY_TIMEOUT)

            # Finsih process if duplication was detected meanwhile
            if not entry.dad:
                logging.info('DUA %s was duplicated, removing...' % entry.dua)
                self.remove_entry(entry)
                return

        # Set DAD flag as finished
        entry.dad = False

        # Announce successful registration to other BBRs
        self.announce(entry)

    def duplicated_found(self, dua):
        '''
        Change the DAD flag for this entry, so that the ongoing DAD process
        removes it
        '''
        for entry in self.entries:
            if dua == entry.dua:
                entry.dad = False

    def announce(self, entry):
        # Send PRO_BB.ntf (9.4.8.4.4)
        asyncio.ensure_future(DUA_HNDLR.send_pro_bb_ntf(entry.dua))

        # Add ND Proxy neighbor
        self.ndproxy.add_del_dua('add', entry.dua, entry.reg_time)

        # Send unsolicited NA
        self.ndproxy.send_na('ff02::1', entry.dua, solicited=False)

        # TODO: save entries to database

    def remove_entry(self, entry=None, dua=None):
        if not entry:
            for entry_ in self.entries:
                if dua == entry_.dua:
                    entry = entry_
        if not entry:
            return
        logging.info(
            'DUA %s with EID %s has been removed' % (entry.dua, entry.eid))
        self.ndproxy.add_del_dua('del', entry.dua)
        self.entries.remove(entry)


class Res_N_DR(resource.Resource):
    '''DUA registration, Thread 1.2 5.23'''

    async def render_post(self, request):
        req_dua = None
        status = DMStatus.ST_UNSPEC

        # Incoming TLVs parsing
        logging.info('in %s req: %s' %
                     (URI.N_DR, ThreadTLV.sub_tlvs_str(request.payload)))

        # BBR Primary/Secondary status
        if 'primary' not in db.get('bbr_status'):
            status = DMStatus.ST_NOT_PRI
        else:
            dua = None
            eid = None
            elapsed = 0

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
            value = ThreadTLV.get_value(request.payload,
                                        TLV.A_TIME_SINCE_LAST_TRANSACTION)
            if value:
                elapsed = struct.unpack('!I', value)[0]

            if eid and dua:
                if DUA_HNDLR.reg_update(eid, dua, elapsed):
                    status = DMStatus.ST_SUCESS
                else:
                    # Duplication detected (resource shortage not contemplated)
                    status = DMStatus.ST_DUP_ADDR

        # Fill and return the response
        payload = ThreadTLV(t=TLV.A_STATUS, l=1, v=[status]).array()
        if req_dua:
            payload += ThreadTLV(t=TLV.A_TARGET_EID, l=16, v=req_dua).array()
        logging.info(
            'out %s rsp: %s' % (URI.N_DR, ThreadTLV.sub_tlvs_str(payload)))
        return aiocoap.Message(code=Code.CHANGED, payload=payload)


class Res_B_BMR(resource.Resource):
    '''Backbone Multicast Listener Report Notification, Thread 1.2 9.4.8.4.5'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info('in %s req: %s' %
                     (URI.B_BMR, ThreadTLV.sub_tlvs_str(request.payload)))

        # Primary BBR shouldn't receive this message
        if not 'primary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE

        # IPv6 Addresses TLV
        addrs = []
        value = ThreadTLV.get_value(request.payload, TLV.A_IPV6_ADDRESSES)
        if value:
            _, addrs = Res_N_MR._parse_addrs(value)

        # Timeout TLV
        timeout = ThreadTLV.get_value(request.payload, TLV.A_TIMEOUT)

        # Register valid addresses
        if addrs and timeout:
            MCAST_HNDLR.reg_update(addrs, timeout)

        return COAP_NO_RESPONSE


class Res_B_BQ(resource.Resource):
    '''Backbone Query, Thread 1.2 9.4.8.4.2'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info('in %s qry: %s' %
                     (URI.B_BQ, ThreadTLV.sub_tlvs_str(request.payload)))

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
        asyncio.ensure_future(
            DUA_HNDLR.send_bb_ans(src_addr, dua, rloc16=rloc16))

        return COAP_NO_RESPONSE


class Res_B_BA(resource.Resource):
    '''Backbone Answer, Thread 1.2 9.4.8.4.3'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info('in %s ans: %s' %
                     (URI.B_BA, ThreadTLV.sub_tlvs_str(request.payload)))

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return COAP_NO_RESPONSE

        dua = None
        rloc16 = None
        eid = None
        elapsed = None
        net_name = None
        value = ThreadTLV.get_value(request.payload, TLV.A_TARGET_EID)
        if value:
            dua = ipaddress.IPv6Address(bytes(value)).compressed
        value = ThreadTLV.get_value(request.payload, TLV.A_RLOC16)
        if value is not None:
            rloc16 = value.hex()
        value = ThreadTLV.get_value(request.payload, TLV.A_ML_EID)
        if value:
            eid = value.hex()
        value = ThreadTLV.get_value(request.payload,
                                    TLV.A_TIME_SINCE_LAST_TRANSACTION)
        if value:
            elapsed = struct.unpack('!I', value)[0]
        value = ThreadTLV.get_value(request.payload, TLV.A_NETWORK_NAME)
        if value:
            net_name = struct.unpack('%ds' % len(value), value)[0].decode()

        # Check if all required TLVs are present
        if None in (dua, eid, elapsed, net_name):
            return COAP_NO_RESPONSE

        logging.info(
            'BB.ans: DUA=%s, ML-EID=%s, Time=%d, Net Name=%s, RLOC16=%s' %
            (dua, eid, elapsed, net_name, rloc16))

        # See if its response to DAD or ADDR_QRY
        if not rloc16:
            # Check if DAD is pending
            entry_eid, _, dad = DUA_HNDLR.find_eid(dua)
            if entry_eid is None or dad is not True:
                # Not expecting an answer for this DUA
                return COAP_NO_RESPONSE
            else:
                # Duplication detected!
                DUA_HNDLR.duplicated_found(dua)
                # Send ADDR_ERR.ntf
                asyncio.ensure_future(
                    DUA_HNDLR.send_addr_err(dua, entry_eid, eid))
        else:
            # Send ADDR_NTF.ans
            bbr_rloc16 = ipaddress.IPv6Address(
                db.get('dongle_rloc')).packed[-2:]
            # If this BBR dongle originated the addr_qry, send addr_ntf to its
            # link local address
            if rloc16 == bbr_rloc16:
                dst = db.get('dongle_ll')
            else:
                dst = NETWORK.get_rloc_from_short(
                    db.get('dongle_prefix'), rloc16)
            asyncio.ensure_future(
                DUA_HNDLR.send_addr_ntf_ans(
                    dst, dua, eid=eid, rloc16=bbr_rloc16, elapsed=elapsed))

        # ACK
        #return COAP_NO_RESPONSE
        return aiocoap.message.Message(no_response=24)


class Res_A_AQ(resource.Resource):
    '''Address Query, Thread 1.2 9.4.8.2.6'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info('in %s qry: %s' %
                     (URI.A_AQ, ThreadTLV.sub_tlvs_str(request.payload)))

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
        dua_prefix = ipaddress.IPv6Address(db.get('dua_prefix').split('/')[0])
        if dua.packed[:8] != dua_prefix.packed[:8]:
            return COAP_NO_RESPONSE

        # See if this DUA is registered by this BBR
        eid, _, dad = DUA_HNDLR.find_eid(dua.compressed)

        # If the DUA is registered, the owner will respond to the query
        if eid and not dad:
            return COAP_NO_RESPONSE

        # Obtain the RLOC16 from the source's RLOC
        rloc16 = ipaddress.IPv6Address(request.remote.sockaddr[0]).packed[-2:]

        # TODO: mantain a cache
        # Propagate Address Query to the Backbone
        await DUA_HNDLR.send_bb_query(dua, rloc16)

        return COAP_NO_RESPONSE


class Res_A_AE(resource.Resource):
    '''Address Error, Thread 1.2 5.23.3.9'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info('in %s ntf: %s' %
                     (URI.A_AE, ThreadTLV.sub_tlvs_str(request.payload)))

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
        dua_prefix = ipaddress.IPv6Address(db.get('dua_prefix').split('/')[0])
        if dua.packed[:8] != dua_prefix.packed[:8]:
            return COAP_NO_RESPONSE

        # Remove entry if it's registered with different EID
        entry_eid, _, dad = DUA_HNDLR.find_eid(dua.compressed)
        if not dad and entry_eid != eid:
            DUA_HNDLR.remove_entry(dua=dua)

        return COAP_NO_RESPONSE


class COAPSERVER(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='coapserver',
            start_keys=['dongle_rloc', 'dongle_prefix'],
            stop_keys=['all_network_bbrs'],
            start_tasks=['serial', 'network', 'diags'],
            stop_tasks=[],
            period=5)

    def kstart(self):
        global DUA_HNDLR
        global MCAST_HNDLR
        logging.info('Starting DUA handler')
        DUA_HNDLR = DUAHandler()
        logging.info('Starting Multicast handler')
        MCAST_HNDLR = MulticastHandler()

        # Set the default BB port if not provided
        if not db.get('bbr_port'):
            db.set('bbr_port', DEFS.PORT_BB)

        # Set All Network BBRs multicast address as per 9.4.8.1
        all_network_bbrs = NETWORK.get_prefix_based_mcast(
            db.get('dongle_prefix'), 3)
        db.set('all_network_bbrs', all_network_bbrs)
        logging.info('Joining All Network BBRs group: %s' % all_network_bbrs)
        MCAST_HNDLR.mcrouter.join_leave_group('join', all_network_bbrs)
        # TODO: update it if dongle_prefix changes

        dua_prefix = db.get('dua_prefix')
        if dua_prefix:
            # Set All Domain BBRs multicast address as per 9.4.8.1
            all_domain_bbrs = NETWORK.get_prefix_based_mcast(dua_prefix, 3)
            db.set('all_domain_bbrs', all_domain_bbrs)
            logging.info('Joining All Domain BBRs group: %s' % all_domain_bbrs)
            MCAST_HNDLR.mcrouter.join_leave_group('join', all_domain_bbrs)
            # TODO: enable radvd

            # Listen for CoAP in Realm-Local All-Routers multicast address
            logging.info('Joining Realm-Local All-Routers group: ff03::2')
            MCAST_HNDLR.mcrouter.join_leave_group('join', 'ff03::2',
                                                  db.get('interior_ifnumber'))

        # Thread side server
        logging.info('Launching CoAP Server in MM port')
        self.server_mm = CoapServer(
            # TODO: bind to RLOC, LL, Realm-Local All-Routers, all_network_bbrs and all_domain_bbrs
            addr='::',
            port=DEFS.PORT_MM,
            resources=[(URI.tuple(URI.N_DR), Res_N_DR()),
                       (URI.tuple(URI.N_MR), Res_N_MR()),
                       (URI.tuple(URI.A_AQ), Res_A_AQ()),
                       (URI.tuple(URI.A_AE), Res_A_AE())])
        logging.info('Launching CoAP Server in MC port')
        self.server_mc = CoapServer(
            # TODO: bind to both RLOC and LL
            addr='::',
            port=DEFS.PORT_MC,
            resources=[(URI.tuple(URI.N_MR), Res_N_MR())])
        logging.info('Launching CoAP Server in BB port')
        self.server_bb = CoapServer(
            # TODO: bind Res_B_BMR to all_network_bbrs
            # TODO: bind Res_B_BQ to all_domain_bbrs
            # TODO: bind Res_B_BA to exterior link-local
            addr='::',
            port=db.get('bbr_port'),
            resources=[(URI.tuple(URI.B_BMR), Res_B_BMR()),
                       (URI.tuple(URI.B_BQ), Res_B_BQ()),
                       (URI.tuple(URI.B_BA), Res_B_BA())])

        if dua_prefix:
            KSH.prefix_handle(
                'prefix',
                'add',
                dua_prefix,
                stable=True,
                on_mesh=True,
                default=True,
                dp=True)

    def kstop(self):
        logging.info('Stopping CoAP Server in MM port')
        self.server_mm.stop()
        logging.info('Stopping CoAP Server in MC port')
        self.server_mc.stop()
        logging.info('Stopping CoAP Server in BB port')
        self.server_bb.stop()

        all_network_bbrs = db.get('all_network_bbrs')
        logging.info('Leaving All Network BBRs group: %s' % all_network_bbrs)
        MCAST_HNDLR.mcrouter.join_leave_group('leave', all_network_bbrs)

        db.set('bbr_status', 'off')
        dua_prefix = db.get('dua_prefix')
        if dua_prefix:
            KSH.prefix_handle(
                'prefix',
                'remove',
                dua_prefix,
                stable=True,
                on_mesh=True,
                default=True,
                dp=True)

            all_domain_bbrs = db.get('all_domain_bbrs')
            logging.info('Leaving All Domain BBRs group: %s' % all_domain_bbrs)
            MCAST_HNDLR.mcrouter.join_leave_group('leave', all_domain_bbrs)

            logging.info('Leaving Realm-Local All-Routers group: ff03::2')
            MCAST_HNDLR.mcrouter.join_leave_group('leave', 'ff03::2',
                                                  db.get('interior_ifnumber'))

        logging.info('Stopping Multicast handler')
        MCAST_HNDLR.stop()
        logging.info('Stopping DUA handler')
        DUA_HNDLR.stop()

    async def periodic(self):
        MCAST_HNDLR.reg_periodic()

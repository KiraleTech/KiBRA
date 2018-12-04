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
from kibra.shell import bash
from kibra.thread import DEFS, TLV, URI
from kibra.tlv import ThreadTLV
from pyroute2 import IPRoute

# Global variables
IP = IPRoute()
MCAST_HNDLR = None


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

        # Remove the address from the presistent list
        maddrs_perm = db.get('maddrs_perm') or []
        if addr in maddrs_perm:
            maddrs_perm.pop(addr)
            db.set('maddrs_perm', maddrs_perm)

        # Remove the existing multicast routes for this address
        self.mcrouter.rem_group_routes(addr)

        # Leave the multicast group
        self.mcrouter.join_leave_group('leave', addr)

        # TODO: Leave the group in the Linux host

        logging.info('Multicast address %s registration removed.' % addr)

    def reg_periodic(self):
        now = datetime.datetime.now().timestamp()
        rem_list = [addr for addr, tout in self.maddrs.items() if tout < now]
        if rem_list:
            for addr in rem_list:
                self.addr_remove(addr)


class Res_N_MR(resource.Resource):
    '''Multicast registration, Thread 1.2 5.24'''

    @staticmethod
    def _parse_addrs(tlv):
        addrs = []
        i = 0
        while i < tlv.length:
            # Check for valid IPv6 address
            try:
                addr = ipaddress.IPv6Address(bytes(tlv.value[i:i + 16]))
            except:
                return DMStatus.ST_INV_ADDR, []
            # Check for valid multicast address with scope > 3
            if addr.is_multicast and tlv.value[i + 1] & 0x0F > 3:
                addrs.append(addr)
            else:
                return DMStatus.ST_INV_ADDR, []
            i += 16
        return DMStatus.ST_SUCESS, addrs

    async def render_post(self, request):
        status = DMStatus.ST_UNSPEC

        # Incoming TLVs parsing
        in_pload = ThreadTLV(data=request.payload)
        logging.info('in %s req: %s' % (URI.N_MR, in_pload))

        # BBR Primary/Secondary status
        if 'primary' not in db.get('bbr_status'):
            status = DMStatus.ST_NOT_PRI
        else:
            addrs = []
            timeout = None
            comm_sid = None

            for tlv in ThreadTLV.sub_tlvs(request.payload):
                if tlv.type is TLV.A_IPV6_ADDRESSES and tlv.length % 16 is 0:
                    ipv6_addressses_tlv = tlv
                    status, addrs = Res_N_MR._parse_addrs(tlv)
                elif tlv.type is TLV.A_TIMEOUT and tlv.length == 4:
                    timeout = tlv.value
                elif tlv.type is TLV.A_COMMISSIONER_SESSION_ID and tlv.length == 2:
                    comm_sid = tlv.value

            # Register valid addresses
            if addrs:
                if timeout and comm_sid:
                    addr_tout = timeout
                else:
                    addr_tout = db.get('mlr_timeout') or DEFS.MIN_MLR_TIMEOUT
                MCAST_HNDLR.reg_update(addrs, addr_tout)
                # Send BMLR.ntf
                timeout_tlv = ThreadTLV(
                    t=TLV.A_TIMEOUT, l=4, v=struct.pack('!I', addr_tout))
                payload = ipv6_addressses_tlv.array() + timeout_tlv.array()
                dst = '%s%%%s' % (db.get('all_network_bbrs'),
                                  db.get('exterior_ifname'))
                client = CoapClient()
                await client.non_request(dst, DEFS.PORT_BB, URI.B_BMR, payload)
                client.stop()

        # Fill and return the response
        out_pload = ThreadTLV(t=TLV.A_STATUS, l=1, v=[status])
        code = Code.CHANGED
        payload = out_pload.array()
        logging.info('out %s rsp: %s' % (URI.N_MR, out_pload))
        return aiocoap.Message(code=code, payload=payload)


class DUAHandler():
    def __init__(self):
        # DUA registrations list
        self.entries = []

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

    async def send_bb_ans(self, mode, dst, dua, rloc16=None):
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

        logging.info(
            'out %s ans: %s' % (URI.B_BA, ThreadTLV.sub_tlvs_str(payload)))
        client = CoapClient()
        if mode == aiocoap.CON:
            await client.con_request(dst, DEFS.PORT_BB, URI.B_BA, payload)
        else:
            await client.non_request(dst, DEFS.PORT_BB, URI.B_BA, payload)
        client.stop()
    
    def remove_entry(self, entry=None, dua=None):
        if not entry:
            for entry_ in self.entries:
                if dua == entry_.dua:
                    entry = entry_
        if not entry_:
            return
        logging.info('DUA %s with EID %s has been removed' % (entry.dua, entry.eid))
        self.entries.remove(entry)

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
        # TODO: add ND Proxy neighbor and send NA
        '''
        bash('ip -6 neigh add proxy %s dev %s' %
                (dua, db.get('interior_ifname')))
        NETWORK.dongle_route_enable(dua)
        '''

        # Send PRO_BB.ntf (9.4.8.4.4)
        asyncio.ensure_future(DUA_HNDLR.send_bb_ans(aiocoap.NON, db.get('all_domain_bbrs'), entry.dua))

        # TODO: save entries to database


class Res_N_DR(resource.Resource):
    '''DUA registration, Thread 1.2 5.23'''

    async def render_post(self, request):
        status = DMStatus.ST_UNSPEC

        # Incoming TLVs parsing
        logging.info(
            'in %s req: %s' % (URI.N_DR, ThreadTLV.sub_tlvs_str(request.payload)))

        # BBR Primary/Secondary status
        if 'primary' not in db.get('bbr_status'):
            status = DMStatus.ST_NOT_PRI
        else:
            dua = None
            eid = None
            elapsed = 0

            # Find TLVs
            for tlv in ThreadTLV.sub_tlvs(request.payload):
                if tlv.type is TLV.A_ML_EID and tlv.length == 8:
                    eid = tlv.value.hex()
                elif tlv.type is TLV.A_TARGET_EID:
                    try:
                        req_dua = bytes(tlv.value)
                        dua = ipaddress.IPv6Address(req_dua)
                    except:
                        status = DMStatus.ST_INV_ADDR
                elif tlv.type is TLV.A_TIME_SINCE_LAST_TRANSACTION and tlv.length == 4:
                    elapsed = struct.unpack('!I', tlv.value)[0]

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
        code = Code.CHANGED
        logging.info(
            'out %s rsp: %s' % (URI.N_DR, ThreadTLV.sub_tlvs_str(payload)))
        return aiocoap.Message(code=code, payload=payload)


class Res_B_BMR(resource.Resource):
    '''Backbone Multicast Listener Report Notification, Thread 1.2 9.4.8.4.5'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info('in %s req: %s' % (URI.B_BMR,
                                     ThreadTLV.sub_tlvs_str(request.payload)))

        # Primary BBR shouldn't receive this message
        if not 'primary' in db.get('bbr_status'):
            return aiocoap.message.NoResponse

        addrs = []
        timeout = None
        for tlv in ThreadTLV.sub_tlvs(request.payload):
            if tlv.type is TLV.A_IPV6_ADDRESSES and tlv.length % 16 is 0:
                _, addrs = Res_N_MR._parse_addrs(tlv)
            elif tlv.type is TLV.A_TIMEOUT and tlv.length == 4:
                timeout = tlv.value

        # Register valid addresses
        if addrs and timeout:
            MCAST_HNDLR.reg_update(addrs, timeout)

        return aiocoap.message.NoResponse


class Res_B_BQ(resource.Resource):
    '''Backbone Query, Thread 1.2 9.4.8.4.2'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s qry: %s' % (URI.B_BQ, ThreadTLV.sub_tlvs_str(request.payload)))

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return aiocoap.message.NoResponse

        dua = None
        rloc16 = None
        for tlv in ThreadTLV.sub_tlvs(request.payload):
            if tlv.type is TLV.A_TARGET_EID and tlv.length == 16:
                dua = ipaddress.IPv6Address(tlv.value)
            elif tlv.type is TLV.A_RLOC16 and tlv.length == 2:
                rloc16 = tlv.value

        if not dua:
            return aiocoap.message.NoResponse

        # Send BB.ans to the requester
        asyncio.ensure_future(DUA_HNDLR.send_bb_ans(aiocoap.CON, request.remote.sockaddr[0], dua, rloc16))

        return aiocoap.message.NoResponse


class Res_B_BA(resource.Resource):
    '''Backbone Answer, Thread 1.2 9.4.8.4.3'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s ans: %s' % (URI.B_BA, ThreadTLV.sub_tlvs_str(request.payload)))

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return aiocoap.message.NoResponse

        dua = None
        rloc16 = None
        eid = None
        elapsed = None
        net_name = None
        for tlv in ThreadTLV.sub_tlvs(request.payload):
            if tlv.type is TLV.A_TARGET_EID and tlv.length == 16:
                dua = ipaddress.IPv6Address(tlv.value).compressed
            elif tlv.type is TLV.A_RLOC16 and tlv.length == 2:
                rloc16 = tlv.value.hex()
            elif tlv.type is TLV.A_ML_EID and tlv.length == 8:
                eid = tlv.value.hex()
            elif tlv.type is TLV.A_TIME_SINCE_LAST_TRANSACTION and tlv.length == 4:
                elapsed = struct.unpack('!I', tlv.value)[0]
            elif tlv.type is TLV.A_NETWORK_NAME and tlv.length <= 16:
                net_name = struct.unpack('%ds' % tlv.length, tlv.value)[0]

        # Check if all required TLVs are present
        if None in (dua, eid, elapsed, net_name):
            return

        logging.info(
            'BB.ans: DUA=%s, ML-EID=%s, Time=%d, Net Name=%s, RLOC16=%s' %
            (dua, eid, elapsed, net_name, rloc16))

        # See if its response to DAD or ADDR_QRY
        if not rloc16:
            # Check if DAD is pending
            eid, _, dad = DUA_HNDLR.find_eid(dua)
            if eid is None or dad is not True:
                # Not expecting an answer for this DUA
                return
            else:
                # Duplication detected!
                DUA_HNDLR.duplicated_found(dua)
                # TODO: send ADDR_ERR.ntf
        else:
            # TODO: send ADDR_NTF.ans
            pass

        return aiocoap.message.NoResponse


class Res_A_AQ(resource.Resource):
    '''Address Query, Thread 1.2 9.4.8.2.6'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s qry: %s' % (URI.A_AQ, ThreadTLV.sub_tlvs_str(request.payload)))

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return aiocoap.message.NoResponse

        # Find sub TLVs
        dua = None
        for tlv in ThreadTLV.sub_tlvs(request.payload):
            if tlv.type is TLV.A_TARGET_EID and tlv.length == 16:
                dua = ipaddress.IPv6Address(bytes(tlv.value))
        if not dua:
            return aiocoap.message.NoResponse

        # Don't process requests for different prefixes than DUA
        dua_prefix = ipaddress.IPv6Address(db.get('dua_prefix').split('/')[0])
        if dua.packed[:8] != dua_prefix.packed[:8]:
            return aiocoap.message.NoResponse

        # See if this DUA is registered by this BBR
        eid, _, dad = DUA_HNDLR.find_eid(dua.compressed)

        # If the DUA is registered, the owner will respond to the query
        if eid and not dad:
            return aiocoap.message.NoResponse

        # Obtain the RLOC16 from the source's RLOC
        rloc16 = ipaddress.IPv6Address(request.remote.sockaddr[0]).packed[-2:]

        # TODO: mantain a cache
        # Propagate Address Query to the Backbone
        await DUA_HNDLR.send_bb_query(dua, rloc16)

        return aiocoap.message.NoResponse


class Res_A_AE(resource.Resource):
    '''Address Error, Thread 1.2 5.23.3.9'''

    async def render_post(self, request):
        # Incoming TLVs parsing
        logging.info(
            'in %s ntf: %s' % (URI.A_AE, ThreadTLV.sub_tlvs_str(request.payload)))

        # Message not handled by Secondary BBR
        if not 'primary' in db.get('bbr_status'):
            return aiocoap.message.NoResponse

        # Find sub TLVs
        dua = None
        eid = None
        for tlv in ThreadTLV.sub_tlvs(request.payload):
            if tlv.type is TLV.A_TARGET_EID and tlv.length == 16:
                dua = ipaddress.IPv6Address(bytes(tlv.value))
            if tlv.type is TLV.A_ML_EID and tlv.length == 8:
                eid = tlv.value.hex()
        if not dua or not eid:
            return aiocoap.message.NoResponse

        # Don't process notifications for different prefixes than DUA
        dua_prefix = ipaddress.IPv6Address(db.get('dua_prefix').split('/')[0])
        if dua.packed[:8] != dua_prefix.packed[:8]:
            return aiocoap.message.NoResponse

        # Remove entry if it's registered with different EID
        entry_eid, _, dad = DUA_HNDLR.find_eid(dua.compressed)
        if not dad and entry_eid != eid:
            DUA_HNDLR.remove_entry(dua=dua)

        return aiocoap.message.NoResponse

class CoapServer():
    '''CoAP Server'''

    def __init__(self, addr, port, resources):
        root = resource.Site()
        for res in resources:
            root.add_resource(res[0], res[1])
        self.task = asyncio.Task(
            aiocoap.Context.create_server_context(root, bind=(addr, port)))

    def stop(self):
        self.task.cancel()


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
        DUA_HNDLR = DUAHandler()
        MCAST_HNDLR = MulticastHandler()

        # Set the default BB port if not provided
        if not db.get('bbr_port'):
            db.set('bbr_port', DEFS.PORT_BB)

        # Set All Network BBRs multicast address as per 9.4.8.1
        all_network_bbrs = NETWORK.get_prefix_based_mcast(
            db.get('dongle_prefix'), 3)
        db.set('all_network_bbrs', all_network_bbrs)
        MCAST_HNDLR.mcrouter.join_leave_group('join', all_network_bbrs)
        # TODO: update it if dongle_prefix changes

        dua_prefix = db.get('dua_prefix')
        if dua_prefix:
            # Set All Domain BBRs multicast address as per 9.4.8.1
            all_domain_bbrs = NETWORK.get_prefix_based_mcast(dua_prefix, 3)
            db.set('all_domain_bbrs', all_domain_bbrs)
            MCAST_HNDLR.mcrouter.join_leave_group('join', all_domain_bbrs)
            # TODO: enable radvd

            # Listen for CoAP in Realm-Local All-Routers multicast address
            MCAST_HNDLR.mcrouter.join_leave_group('join', 'ff03::2',
                db.get('interior_ifnumber'))

        # Thread side server
        self.server_mm = CoapServer(
            # TODO: bind to RLOC, LL, Realm-Local All-Routers, all_network_bbrs and all_domain_bbrs
            addr='::',
            port=DEFS.PORT_MM,
            resources=[(URI.tuple(URI.N_DR), Res_N_DR()),
                       (URI.tuple(URI.N_MR), Res_N_MR()),
                       (URI.tuple(URI.A_AQ), Res_A_AQ()),
                       (URI.tuple(URI.A_AE), Res_A_AE())])
        self.server_mc = CoapServer(
            # TODO: bind to both RLOC and LL
            addr='::',
            port=DEFS.PORT_MC,
            resources=[(URI.tuple(URI.N_MR), Res_N_MR())])
        self.server_bb = CoapServer(
            # TODO: bind Res_B_BA to exterior link-local
            addr=all_network_bbrs,
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
                dp=True)

    def kstop(self):
        self.server_mm.stop()
        self.server_mc.stop()
        self.server_bb.stop()
        MCAST_HNDLR.mcrouter.join_leave_group('leave', db.get('all_network_bbrs'))
        db.set('bbr_status', 'off')
        dua_prefix = db.get('dua_prefix')
        if dua_prefix:
            KSH.prefix_handle(
                'prefix',
                'remove',
                dua_prefix,
                stable=True,
                on_mesh=True,
                dp=True)
            MCAST_HNDLR.mcrouter.join_leave_group('leave', db.get('all_domain_bbrs'))
            MCAST_HNDLR.mcrouter.join_leave_group('leave', 'ff03::2', db.get('interior_ifnumber'))

    async def periodic(self):
        MCAST_HNDLR.reg_periodic()

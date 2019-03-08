import asyncio
import copy
import logging
import time
import ipaddress

import kibra.database as db
import kibra.network as NETWORK
from kibra.coapclient import CoapClient
from kibra.ktask import Ktask
from kibra.shell import bash
from kibra.thread import DEFS, TLV, URI
from kibra.tlv import ThreadTLV

VALUES = [
    TLV.D_MAC_ADDRESS, TLV.D_ROUTE64, TLV.D_LEADER_DATA,
    TLV.D_IPV6_ADRESS_LIST, TLV.D_CHILD_TABLE
]
PET_DIAGS = ThreadTLV(t=TLV.D_TYPE_LIST, l=len(VALUES), v=VALUES).array()

VALUES = [
    TLV.C_CHANNEL, TLV.C_PAN_ID, TLV.C_EXTENDED_PAN_ID, TLV.C_NETWORK_NAME,
    TLV.C_NETWORK_MESH_LOCAL_PREFIX, TLV.C_ACTIVE_TIMESTAMP,
    TLV.C_SECURITY_POLICY
]
PET_ACT_DATASET = ThreadTLV(t=TLV.C_GET, l=len(VALUES), v=VALUES).array()

PET_NET_DATA = ThreadTLV(
    t=TLV.D_TYPE_LIST, l=1, v=[TLV.D_NETWORK_DATA]).array()

NODE_INACTIVE_MS = 90000

DIAGS_DB = {}


def _epoch_ms():
    return int(time.mktime(time.localtime()) * 1000)


class DIAGS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='diags',
            start_keys=['dongle_ll', 'interior_ifname'],
            start_tasks=['serial', 'network'],
            period=1)
        self.petitioner = CoapClient()
        self.br_rloc16 = ''
        self.br_permanent_addr = ''
        self.br_internet_access = 'offline'
        self.nodes_list = []
        self.last_diags = []
        self.last_time = 0

    def kstart(self):
        ll_addr = ipaddress.IPv6Address(db.get('dongle_ll')).compressed
        self.br_permanent_addr = '%s%%%s' % (ll_addr,
                                             db.get('interior_ifname'))
        DIAGS_DB['nodes'] = []
        # Delete old values to prevent MDNS from using them before obtaning
        # the updated ones
        db.delete('dongle_xpanid')
        db.delete('dongle_netname')
        db.set('bbr_status', 'off')

    def kstop(self):
        self.petitioner.stop()
        #self.petitioner.loop.stop()

    async def periodic(self):
        # Check internet connection
        '''
        ping = int(
            str(
                bash('ping -c 1 -s 0 -I %s -q 8.8.8.8 > /dev/null ; echo $?' %
                     db.get('exterior_ifname'))))
        self.br_internet_access = 'online' if ping is 0 else 'offline'
        '''
        # Diags
        response = await self.petitioner.con_request(
            self.br_permanent_addr, DEFS.PORT_MM, URI.D_DG, PET_DIAGS)
        if not response:
            return

        # Save BR RLOC16
        rloc16 = ThreadTLV.get_value(response, TLV.D_MAC_ADDRESS)
        # TODO: update dongle_rloc and Linux address
        if rloc16:
            self.br_rloc16 = '%02x%02x' % (rloc16[0], rloc16[1])

        # More requests if changes found in the network or if some time has
        # passed
        current_time = _epoch_ms()
        if response != self.last_diags or current_time > (
                self.last_time + NODE_INACTIVE_MS):
            self.last_diags = response
            self.last_time = current_time
            self._parse_diags(response)
            # Network Data get
            response = await self.petitioner.con_request(
                self.br_permanent_addr, DEFS.PORT_MM, URI.D_DG, PET_NET_DATA)
            self._parse_net_data(response)
            # Active Data Set get
            response = await self.petitioner.con_request(
                self.br_permanent_addr, DEFS.PORT_MM, URI.C_AG,
                PET_ACT_DATASET)
            self._parse_active_dataset(response)
            # Update nodes info
            # TODO: this is commented not to generate noise in the test captures
            '''
            for rloc16 in self.nodes_list:
                if rloc16 == self.br_rloc16:
                    continue
                node_rloc = NETWORK.get_rloc_from_short(
                    db.get('dongle_prefix'), rloc16)
                response = await self.petitioner.con_request(
                    node_rloc, DEFS.PORT_MM, URI.D_DG, PET_DIAGS)
                self._parse_diags(response)
                time.sleep(0.2)
            '''
            self._mark_old_nodes()
            
    def _parse_diags(self, tlvs):
        now = _epoch_ms()
        json_node_info = {}
        json_node_info['roles'] = []
        json_node_info['routes'] = []
        json_node_info['addresses'] = []
        json_node_info['children'] = []
        leader_rloc16 = None

        # Address16 TLV
        value = ThreadTLV.get_value(tlvs, TLV.D_MAC_ADDRESS)
        if value:
            json_node_info['rloc16'] = '%02x%02x' % (value[0], value[1])
            if value[1] == 0:
                json_node_info['roles'].append('router')
            else:
                json_node_info['roles'].append('end-device')
        else:
            return

        # Route 64 TLV
        value = ThreadTLV.get_value(tlvs, TLV.D_ROUTE64)
        if value:
            router_id_mask = bin(int.from_bytes(value[1:9], byteorder='big'))
            router_ids = [
                63 - i for i, v in enumerate(router_id_mask[:1:-1]) if int(v)
            ][::-1]
            qualities = value[9:]
            for router_id in router_ids:
                router_quality = int(qualities.pop(0))
                q_out = (router_quality & 0xC0) >> 6
                q_in = (router_quality & 0x30) >> 4
                cost = router_quality & 0x0F
                if q_in is not 0 and q_out is not 0:
                    json_router_info = {}
                    json_router_info['id'] = '%u' % router_id
                    json_router_info['target'] = '%04x' % (router_id << 10)
                    json_router_info['inCost'] = '%u' % q_in
                    json_node_info['routes'].append(json_router_info)
                    if json_router_info['target'] not in self.nodes_list:
                        self.nodes_list.append(json_router_info['target'])
                elif q_in is 0 and q_out is 0 and cost is 1:
                    json_node_info['id'] = '%u' % router_id

        # Leader Data TLV
        value = ThreadTLV.get_value(tlvs, TLV.D_LEADER_DATA)
        if value:
            leader_rloc16 = '%04x' % (value[7] << 10)

        # IPv6 Address List TLV
        value = ThreadTLV.get_value(tlvs, TLV.D_IPV6_ADRESS_LIST)
        if value:
            addresses = [value[i:i + 16] for i in range(0, len(value), 16)]
            for addr in addresses:
                str_addr = ipaddress.IPv6Address(
                    int.from_bytes(addr, byteorder='big')).compressed
                json_node_info['addresses'].append(str_addr)

        # Now process child info, because json_node_info['rloc16'] is needed
        # Child Table TLV
        value = ThreadTLV.get_value(tlvs, TLV.D_CHILD_TABLE)
        if value:
            children = [value[i:i + 3] for i in range(0, len(value), 3)]
            for child in children:
                json_child_info = {}
                rloc_high = bytearray.fromhex(json_node_info['rloc16'])[0]
                rloc_high |= child[0] & 0x01
                json_child_info['rloc16'] = '%02x%02x' % (rloc_high, child[1])
                json_child_info['timeout'] = '%u' % (
                    child[0] >> 3)  # TODO: convert to seconds
                json_node_info['children'].append(json_child_info)

        # Update other informations
        if leader_rloc16 and json_node_info['rloc16'] in leader_rloc16:
            json_node_info['roles'].append('leader')
        if json_node_info['rloc16'] in self.br_rloc16:
            json_node_info['roles'].append('border-router')
            json_node_info['internetAccess'] = self.br_internet_access
        json_node_info['active'] = 'yes'
        json_node_info['lastSeen'] = now

        # Add node to database
        self._add_node(json_node_info)

        # Add children to database
        for child in json_node_info['children']:
            independent_child = copy.deepcopy(child)
            independent_child['roles'] = ['end-device']
            independent_child['active'] = 'yes'
            independent_child['lastSeen'] = now
            self._add_node(independent_child)

    def _add_node(self, json_node_info):
        logging.debug('Updated data for node %s.', json_node_info['rloc16'])
        # Find previous node data
        for index, node in enumerate(DIAGS_DB['nodes']):
            if node['rloc16'] in json_node_info['rloc16']:
                # Retrieve firstSeen
                if 'firstSeen' in node:
                    json_node_info['firstSeen'] = node['firstSeen']
                # Remove old data
                DIAGS_DB['nodes'].pop(index)
        # Set firstSeen
        if 'firstSeen' not in json_node_info:
            logging.info('New node! "%s"', json_node_info['rloc16'])
            json_node_info['firstSeen'] = _epoch_ms()
        # Set new data
        DIAGS_DB['nodes'].append(json_node_info)

    def _mark_old_nodes(self):
        now = _epoch_ms()
        for i, node in enumerate(DIAGS_DB['nodes']):
            if node['active'] is 'yes':
                if now - node['lastSeen'] > NODE_INACTIVE_MS:
                    logging.info('Node %s became inactive.', node['rloc16'])
                    # Remove from database
                    DIAGS_DB['nodes'][i]['active'] = 'no'
                    # Remove from nodes_list
                    self.nodes_list = [
                        n for n in self.nodes_list if n not in node['rloc16']
                    ]

    def _parse_active_dataset(self, payload):
        # No response to /c/ag
        if payload is None or b'':
            db.set('dongle_secpol', '0')
        # Response present
        else:
            value = ThreadTLV.get_value(payload, TLV.C_CHANNEL)
            if value:
                db.set('dongle_channel', int(value[2]))
            value = ThreadTLV.get_value(payload, TLV.C_PAN_ID)
            if value:
                db.set('dongle_panid',
                       '0x' + ''.join('%02x' % byte for byte in value))
            value = ThreadTLV.get_value(payload, TLV.C_EXTENDED_PAN_ID)
            if value:
                db.set('dongle_xpanid',
                       '0x' + ''.join('%02x' % byte for byte in value))
            value = ThreadTLV.get_value(payload, TLV.C_NETWORK_NAME)
            if value:
                db.set('dongle_netname',
                       ''.join('%c' % byte for byte in value))
            value = ThreadTLV.get_value(payload,
                                        TLV.C_NETWORK_MESH_LOCAL_PREFIX)
            if value:
                prefix_bytes = bytes(value) + bytes(8)
                prefix_addr = ipaddress.IPv6Address(prefix_bytes)
                db.set('dongle_prefix', prefix_addr.compressed + '/64')
            value = ThreadTLV.get_value(payload, TLV.C_ACTIVE_TIMESTAMP)
            value = ThreadTLV.get_value(payload, TLV.C_SECURITY_POLICY)
            if value:
                db.set('dongle_secpol', value.hex())

    def _parse_net_data(self, tlvs):
        value = ThreadTLV.get_value(tlvs, TLV.D_NETWORK_DATA)
        if value:
            for tlv in ThreadTLV.sub_tlvs(value):
                if tlv.type >> 1 is TLV.N_SERVICE:
                    # Detect BBR Dataset encoding
                    if (tlv.value[0] >> 7 and tlv.value[1] is 1
                            and tlv.value[2] is 1):
                        server_tlvs = ThreadTLV.sub_tlvs(tlv.value[3:])
                        '''BBR is primary if there is only one Server TLV in the
                        BBR Dataset and the RLOC16 is the same as ours'''
                        if len(server_tlvs) == 1:
                            node_rloc = ipaddress.IPv6Address(
                                db.get('dongle_rloc')).packed
                            if node_rloc[14:16] == server_tlvs[0].value[0:2]:
                                if 'primary' not in db.get('bbr_status'):
                                    logging.info('Setting this BBR as Primary')
                                db.set('bbr_status', 'primary')
                                return
            if 'secondary' not in db.get('bbr_status'):
                logging.info('Setting this BBR as Secondary')
        db.set('bbr_status', 'secondary')

import asyncio
import copy
import logging
import time
from ipaddress import IPv6Address

from aiocoap import CON, Context, Message
from aiocoap.numbers.codes import Code

import kibra.database as db
from kibra.ktask import Ktask
from kibra.shell import bash
from kibra.thread import TLV
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

URI_D_DG = '/d/dg'
URI_C_AG = '/c/ag'

NODE_INACTIVE_MS = 90000

DIAGS_DB = {}


def _epoch_ms():
    return int(time.mktime(time.localtime()) * 1000)


class DiagnosticPetition():
    '''Perform CoAP petitions to the Thread Diagnostics port'''

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.protocol = None
        self.response = None

    async def request(self, addr, path, payload=''):
        '''Client request'''
        if self.protocol is None:
            self.protocol = await Context.create_client_context()
        req = Message(code=Code.POST, mtype=CON, payload=payload)
        req.set_request_uri(
            uri='coap://[%s]:61631%s' % (addr, path), set_uri_host=False)
        try:
            response = await self.protocol.request(req).response
        except Exception:
            logging.debug('No response from %s', addr)
            self.response = None
        else:
            logging.debug('%s responded with %s.', addr, response.code)
            self.response = response.payload

    def petition(self, addr, path, payload):
        '''Petition'''
        self.loop.run_until_complete(self.request(addr, path, payload))
        return self.response


class DIAGS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='diags',
            start_keys=['dongle_ll', 'interior_ifname'],
            start_tasks=['serial', 'network'],
            period=5)
        self.petitioner = DiagnosticPetition()
        self.br_rloc16 = ''
        self.br_permanent_addr = ''
        self.br_internet_access = 'offline'
        self.nodes_list = []
        self.last_diags = []
        self.last_time = 0

    def kstart(self):
        self.br_permanent_addr = '%s%%%s' % (IPv6Address(
            db.get('dongle_ll')).compressed, db.get('interior_ifname'))
        DIAGS_DB['nodes'] = []
        # Delete old values to prevent MDNS from using them before obtaning
        # the updated ones
        db.delete('dongle_xpanid')
        db.delete('dongle_netname')

    def kstop(self):
        self.petitioner.protocol.shutdown()
        self.petitioner.loop.stop()

    def periodic(self):
        # Check internet connection
        ping = int(
            str(
                bash('ping -c 1 -s 0 -I %s -q 8.8.8.8 > /dev/null ; echo $?' %
                     db.get('exterior_ifname'))))
        self.br_internet_access = 'online' if ping is 0 else 'offline'
        # Diags
        response = self.petitioner.petition(self.br_permanent_addr, URI_D_DG,
                                            PET_DIAGS)
        if not response:
            return
        response = ThreadTLV.sub_tlvs(response)
        for tlv in response:
            # Save BR RLOC16
            if tlv.type is TLV.D_MAC_ADDRESS:
                self.br_rloc16 = '%02x%02x' % (tlv.value[0], tlv.value[1])
            # Ignore ID sequence from Route 64 TLV
            elif tlv.type is TLV.D_ROUTE64:
                tlv.value[0] = 0
        # More requests if changes found in the network or if some time has passed
        current_diags = set(str(tlv) for tlv in response)
        current_time = _epoch_ms()
        if current_diags != self.last_diags or current_time > (
                self.last_time + NODE_INACTIVE_MS):
            self.last_diags = current_diags
            self.last_time = current_time
            self._parse_diags(response)
            # Active Data Set get
            response = self.petitioner.petition(self.br_permanent_addr,
                                                URI_C_AG, PET_ACT_DATASET)
            self._parse_active_dataset(response)
            # Update nodes info
            for rloc16 in self.nodes_list:
                if rloc16 == self.br_rloc16:
                    continue
                node_rloc = IPv6Address(
                    int(db.get('dongle_prefix') + '000000fffe00' + rloc16,
                        16)).compressed
                response = self.petitioner.petition(node_rloc, URI_D_DG,
                                                    PET_DIAGS)
                if response:
                    response = ThreadTLV.sub_tlvs(response)
                    self._parse_diags(response)
                time.sleep(0.2)
            self._mark_old_nodes()

    def _parse_diags(self, tlvs):
        now = _epoch_ms()
        json_node_info = {}
        json_node_info['roles'] = []
        json_node_info['routes'] = []
        json_node_info['addresses'] = []
        json_node_info['children'] = []

        for tlv in tlvs:
            # Address16 TLV
            if tlv.type is TLV.D_MAC_ADDRESS:
                json_node_info['rloc16'] = '%02x%02x' % (tlv.value[0],
                                                         tlv.value[1])
                if tlv.value[1] is 0:
                    json_node_info['roles'].append('router')
                else:
                    json_node_info['roles'].append('end-device')
            # Route 64 TLV
            elif tlv.type is TLV.D_ROUTE64:
                router_id_mask = bin(
                    int.from_bytes(tlv.value[1:9], byteorder='big'))
                router_ids = [
                    63 - i for i, v in enumerate(router_id_mask[:1:-1])
                    if int(v)
                ][::-1]
                qualities = tlv.value[9:]
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
            elif tlv.type is TLV.D_LEADER_DATA:
                leader_rloc16 = '%04x' % (tlv.value[7] << 10)
            # IPv6 Address List TLV
            elif tlv.type is TLV.D_IPV6_ADRESS_LIST:
                addresses = [
                    tlv.value[i:i + 16] for i in range(0, tlv.length, 16)
                ]
                for addr in addresses:
                    str_addr = IPv6Address(
                        int.from_bytes(addr, byteorder='big')).compressed
                    json_node_info['addresses'].append(str_addr)

        # Now process child info, because json_node_info['rloc16'] is needed
        for tlv in tlvs:
            # Child Table TLV
            if tlv.type is TLV.D_CHILD_TABLE:
                children = [
                    tlv.value[i:i + 3] for i in range(0, tlv.length, 3)
                ]
                for child in children:
                    json_child_info = {}
                    rloc_high = bytearray.fromhex(json_node_info['rloc16'])[0]
                    rloc_high |= child[0] & 0x01
                    json_child_info['rloc16'] = '%02x%02x' % (rloc_high,
                                                              child[1])
                    json_child_info['timeout'] = '%u' % (
                        child[0] >> 3)  # TODO: convert to seconds
                    json_node_info['children'].append(json_child_info)

        # Update other informations
        if json_node_info['rloc16'] in leader_rloc16:
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
        if not 'firstSeen' in json_node_info:
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
            db.set('bagent_tis', 0)
            db.set('bagent_cm', 0)
        # Response present
        else:
            # If the BR is not a REED and responds to /c/ag, TIS=2
            if self.br_rloc16[-2] is '00':
                db.set('bagent_tis', 2)
            # Update other parameters
            tlvs = ThreadTLV.sub_tlvs(payload)
            for tlv in tlvs:
                if tlv.type is TLV.C_CHANNEL:
                    db.set('dongle_channel', int(tlv.value[2]))
                if tlv.type is TLV.C_PAN_ID:
                    db.set('dongle_panid',
                           '0x' + ''.join('%02x' % byte for byte in tlv.value))
                if tlv.type is TLV.C_EXTENDED_PAN_ID:
                    db.set('dongle_xpanid',
                           '0x' + ''.join('%02x' % byte for byte in tlv.value))
                if tlv.type is TLV.C_NETWORK_NAME:
                    db.set('dongle_netname',
                           ''.join('%c' % byte for byte in tlv.value))
                if tlv.type is TLV.C_NETWORK_MESH_LOCAL_PREFIX:
                    db.set('dongle_prefix',
                           ''.join('%02x' % byte for byte in tlv.value))
                if tlv.type is TLV.C_ACTIVE_TIMESTAMP:
                    db.set('bagent_at',
                           ''.join('%02x' % byte for byte in tlv.value))
                if tlv.type is TLV.C_SECURITY_POLICY:
                    db.set('bagent_cm', (tlv.value[2] >> 2) & 0x01)

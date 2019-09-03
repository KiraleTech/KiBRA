'''Parse KiNOS messages sent by BR in syslog format'''
import asyncio
import ipaddress
import json
import logging
import re
import socket
import struct

import kibra.database as db
import kibra.network as NETWORK
from kibra.ktask import Ktask

SYSLOG_PORT = 514

# KiNOS messages
SYSLOG_MSG_ID_CACHE_DEL = 0
SYSLOG_MSG_ID_CACHE_ADD = 1
SYSLOG_MSG_ID_BBR_PRI = 2
SYSLOG_MSG_ID_BBR_SEC = 3
SYSLOG_MSG_ID_ALOC_DEL = 4  # Not used
SYSLOG_MSG_ID_ALOC_ADD = 5  # Not used
SYSLOG_MSG_ID_UNICAST_SYS_ADD = 6
SYSLOG_MSG_ID_AOPD_SAVED = 7
SYSLOG_MSG_ID_JOIN_STATUS_OK = 8
SYSLOG_MSG_ID_JOIN_STATUS_ERR = 9

IPPROTO_IPV6 = 41


def _parse_active_dataset(payload):
    channel, panid, sec_policy, mesh_prefix, xpanid, net_name = payload.split(' | ')

    db.set('ncp_channel', int(channel))
    db.set('ncp_panid', panid)
    db.set('ncp_secpol', sec_policy)
    prefix_bytes = bytes.fromhex(mesh_prefix.replace('0x', '')) + bytes(8)
    prefix_addr = ipaddress.IPv6Address(prefix_bytes)
    db.set('ncp_prefix', prefix_addr.compressed + '/64')
    # TODO: take actions upon a mesh prefix change
    db.set('ncp_xpanid', xpanid)
    db.set('ncp_netname', net_name)


def _process_message(msgid, uptime, payload):
    logging.debug('msgid = %s, uptime = %s, payload = %s' % (msgid, uptime, payload))

    if msgid == SYSLOG_MSG_ID_CACHE_DEL:
        cached_eids = db.get('ncp_eid_cache')
        try:
            cached_eids.remove(payload)
            db.set('ncp_eid_cache', cached_eids)
        except:
            pass # It didn't exist in the list
        logging.info('Address %s is not cached anymore.' % payload)
    elif msgid == SYSLOG_MSG_ID_CACHE_ADD:
        cached_eids = db.get('ncp_eid_cache')
        cached_eids.append(payload)
        db.set('ncp_eid_cache', cached_eids)
        logging.info('Address %s is now cached.' % payload)
    elif msgid == SYSLOG_MSG_ID_BBR_PRI:
        if 'primary' not in db.get('bbr_status'):
            db.set('bbr_status', 'primary')
            logging.info('This BBR is now Primary.')
    elif msgid == SYSLOG_MSG_ID_BBR_SEC:
        if 'secondary' not in db.get('bbr_status'):
            db.set('bbr_status', 'secondary')
            logging.info('This BBR is now Secondary.')
    elif msgid == SYSLOG_MSG_ID_UNICAST_SYS_ADD:
        NETWORK.assign_addr(payload)
    elif msgid == SYSLOG_MSG_ID_AOPD_SAVED:
        _parse_active_dataset(payload)
        logging.info('Active dataset changed.')
    elif msgid == SYSLOG_MSG_ID_JOIN_STATUS_OK:
        db.set('ncp_status', 'joined')
        logging.info('Device just joined to the Thread network')
    elif msgid == SYSLOG_MSG_ID_JOIN_STATUS_ERR:
        # TODO: notify user
        logging.info('Device could not join to the Thread network')


class Syslog_Parser:
    def __init__(self, ll_addr):
        self.run = False
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ll_addr = (ll_addr, SYSLOG_PORT, 0, int(db.get('interior_ifnumber')))

        try:
            self.sock.bind(ll_addr)
            self.run = True
        except Exception as exc:
            logging.error('Could not launch Syslog_Parser. Error: %s' % exc)
            return

        self.pattern = re.compile(
            r'<62>1 - - - - - (\d+) \[origin enterpriseId="49166"\]\[meta sysUpTime="(\d+)"\]\s?(.*)'
        )

        asyncio.get_event_loop().run_in_executor(None, self.run_daemon)

    def run_daemon(self):
        while self.run:
            request = self.sock.recvfrom(1280)
            try:
                message = request[0].decode()
            except:
                continue
            match = self.pattern.match(message)
            if match:
                msgid, uptime, payload = match.groups()
                _process_message(
                    int(msgid), int(uptime) / 100, payload.replace('BOM', '')
                )

    def stop(self):
        self.run = False
        self.sock.close()


class SYSLOG(Ktask):
    def __init__(self):
        Ktask.__init__(
            self, name='syslog', start_keys=[], start_tasks=['network'], period=1
        )
        self.syslog = None

    def kstart(self):
        db.set('bbr_status', 'off')
        db.delete('ncp_rloc')
        db.delete('ncp_mleid')
        # Get interior link-local address
        iface_addrs = NETWORK.get_addrs(db.get('interior_ifname'), socket.AF_INET6)
        for addr in iface_addrs:
            if addr.startswith('fe80'):
                # Start listening to KiNOS syslog messages
                self.syslog = Syslog_Parser(addr)

    def kstop(self):
        self.syslog.stop()

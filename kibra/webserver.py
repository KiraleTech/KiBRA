import asyncio
import http.server
import ipaddress
import json
import logging
import os
import socket
import socketserver
import struct
import sys
import time
import urllib
import xml.etree.ElementTree

import kibra
import kibra.database as db
import zeroconf
from kibra.diags import DIAGS_DB
from kibra.ksh import bbr_dataset_update, send_cmd
from kibra.network import set_ext_iface
from kibra.shell import bash

BBR_HDP_ADDR = ('ff02::114', 12345)
WEB_PORT = 80
PUBLIC_DIR = os.path.dirname(sys.argv[0]) + '/public'
LEASES_PATH = '/var/lib/dibbler/server-AddrMgr.xml'

ANNOUNCER = None
HTTPD = None

IPPROTO_IPV6 = 41


def _get_leases():
    leases = {}
    leases['leases'] = []
    addrs = xml.etree.ElementTree.parse(LEASES_PATH).getroot()
    if not addrs:
        return leases
    for client in addrs.iter('AddrClient'):
        for addr_ia in client.iter('AddrIA'):
            if addr_ia.get('ifacename') == db.get('interior_ifname'):
                for addr in addr_ia.iter('AddrAddr'):
                    node = {}
                    node['duid'] = addr_ia.find('duid').text
                    node['expires'] = 1000 * (
                        int(addr.get('timestamp')) + int(addr.get('valid')))
                    node['gua'] = addr.text
                    if node['expires'] > time.time():
                        leases['leases'].append(node)
    return leases


class V6Server(socketserver.TCPServer):
    address_family = socket.AF_INET6


class WebServer(http.server.SimpleHTTPRequestHandler):
    '''
    def do_POST(self):
        # TODO: by the moment using GET only
        pass
    '''

    def do_GET(self):
        binary = False
        if self.path == '/':
            self.path = '/index.html'
        file_path = '%s%s' % (PUBLIC_DIR, self.path.replace('/assets', ''))
        mime_type = 'text/json'

        try:
            # Parse URL fields
            req = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

            # Different actions
            if self.path.startswith('/api'):
                for key in req.keys():
                    if not key in db.modifiable_keys():
                        self.send_response(http.HTTPStatus.BAD_REQUEST)
                        return
                # Apply incoming changes
                modif_keys = set()
                for key, value in req.items():
                    if str(db.get(key)) != value[0]:
                        db.set(key, value[0])
                        modif_keys.add(key)
                # Special actions
                if not set(['mlr_timeout', 'rereg_delay'
                            ]).isdisjoint(modif_keys):
                    bbr_dataset_update()
                data = 'OK'
            elif self.path.startswith('/ksh'):
                cmd = req.get('c', None)
                if cmd:
                    data = '\n'.join(send_cmd(cmd[0]))
                else:
                    return
            elif self.path.startswith('/ping'):
                dst = req.get('dst',
                              ['0100::'])[0]  # Discard address by default
                size = req.get('sz', ['0'])[0]  # Zero size by default
                hl = req.get('hl', ['255'])[0]  # Hop limit 255 by default
                iface = db.get('exterior_ifname')
                bash('ping -c1 -W2 -s%s -t%s -I%s %s' % (size, hl, iface, dst))
                data = 'OK'
            elif self.path.startswith('/radvd'):
                off = req.get('off')
                backhaul = req.get('bh')
                domain = req.get('dm')
                if off:
                    bash('service radvd stop')
                elif backhaul and domain:
                    if not db.get('exterior_ifname'):
                        set_ext_iface()
                    with open('/etc/radvd.conf', 'w') as file_:
                        file_.write(
                            'interface %s {\n' % db.get('exterior_ifname'))
                        file_.write('  AdvSendAdvert on;\n')
                        file_.write('  prefix %s { AdvAutonomous on; };\n' %
                                    backhaul[0])
                        file_.write('  prefix %s { AdvAutonomous off; };\n' %
                                    domain[0])
                        file_.write('};\n')
                    bash('echo 1 > /proc/sys/net/ipv6/conf/all/forwarding')
                    bash('service radvd restart')
                else:
                    return
                data = 'OK'
            elif self.path == '/logs':
                # TODO: fancy colourfull autorefresh logs page
                with open(db.LOG_FILE, 'r') as file_:
                    data = file_.read()
                mime_type = 'text/plain'
            elif self.path == '/db/cfg':
                data = db.dump()
            elif self.path == '/db/nodes':
                data = json.dumps(DIAGS_DB, indent=2)
            elif self.path == '/db/leases':
                data = json.dumps(_get_leases(), indent=2)
            elif os.path.isfile(file_path):
                if self.path.endswith(".html"):
                    mime_type = 'text/html'
                if self.path.endswith(".png"):
                    mime_type = 'image/png'
                    binary = True
                if self.path.endswith(".js"):
                    mime_type = 'application/javascript'
                if self.path.endswith(".css"):
                    mime_type = 'text/css'
                with open(file_path, 'rb' if binary else 'r') as file_:
                    data = file_.read()
            else:
                self.send_response(http.HTTPStatus.NOT_FOUND)
                return
        except:
            self.send_response(http.HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self.send_response(http.HTTPStatus.OK)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', mime_type)
        self.end_headers()
        if not binary:
            data = data.encode()
        self.wfile.write(data)

    # Disable logging
    def log_request(self, code):
        pass

    def log_message(self, fmt, *args):
        pass


class HDP_Announcer():
    def __init__(self):
        self.run = False
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        ifn = struct.pack('I', int(db.get('exterior_ifnumber')))
        self.sock.setsockopt(IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifn)
        group = socket.inet_pton(socket.AF_INET6, BBR_HDP_ADDR[0]) + ifn
        self.sock.setsockopt(IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)

        ll_addr = ('', BBR_HDP_ADDR[1], 0, 0)
        try:
            self.sock.bind(ll_addr)
            self.run = True
        except Exception as exc:
            logging.error('Could not launch HDP Announcer. Error: %s' % exc)

    def start(self, props):
        while self.run:
            request = self.sock.recvfrom(1024)
            if request[0].decode() == 'BBR':
                db.set('discovered', 1)
                dst_addr = request[1][0]
                dst_port = request[1][1]
                logging.info('HDP request from %s' % dst_addr)
                self.sock.sendto(
                    json.dumps(props).encode(), (dst_addr, dst_port))

    def stop(self):
        self.run = False


def start():
    global HTTPD, ANNOUNCER

    print('Loading web server...')
    while not HTTPD:
        # The port may have not been closed from the previous session
        # TODO: properly close server when stopping app
        try:
            HTTPD = V6Server(('', WEB_PORT), WebServer)
        except OSError:
            time.sleep(1)
    asyncio.get_event_loop().run_in_executor(None, HTTPD.serve_forever)
    print('Webserver is up')

    props = {'ven': 'Kirale', 'mod': 'KiBRA', 'ver': kibra.__version__}
    '''
    # Announce via mDNS
    ipv4_addr = db.get('exterior_ipv4')
    if ipv4_addr:
        ANNOUNCER = zeroconf.Zeroconf()
        type_ = '_bbr._tcp.local.'
        name = 'Kirale-KiBRA %s' % int(time.time())
        service = zeroconf.ServiceInfo(
            type_=type_,
            name='%s.%s' % (name, type_),
            address=ipaddress.IPv4Address(ipv4_addr).packed,
            port=WEB_PORT,
            properties=props)
        ANNOUNCER.register_service(service)
        print('%s service announced via mDNS' % name)
    '''

    # Announce via Harness Discovery Protocol
    props['add'] = db.get('exterior_ipv6_ll')
    props['por'] = WEB_PORT
    ANNOUNCER = HDP_Announcer()
    asyncio.get_event_loop().run_in_executor(None, ANNOUNCER.start, props)
    print('BBR announced via HDP')


def stop():
    global ANNOUNCER

    print('Stopping web server...')
    ANNOUNCER.stop()
    HTTPD.server_close()

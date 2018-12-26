import asyncio
import http.server
import json
import logging
import os
import socket
import socketserver
import sys
import time
import xml.etree.ElementTree
import urllib
import zeroconf

import kibra.database as db
from kibra.diags import DIAGS_DB
from kibra.ksh import bbr_dataset_update, send_cmd
from kibra.shell import bash

WEB_PORT = 80
KIBRA_VERSION = '1.2.0'
PUBLIC_DIR = os.path.dirname(sys.argv[0]) + '/public'
LEASES_PATH = '/var/lib/dibbler/server-AddrMgr.xml'

ANNOUNCER = None
HTTPD = None


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
            if self.path.startswith('/api'):
                req = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query)
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
                req = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query)
                cmd = req.get('c', None)
                if cmd:
                    data = '\n'.join(send_cmd(cmd[0]))
                else:
                    return
            elif self.path.startswith('/ping'):
                req = urllib.parse.parse_qs(
                    urllib.parse.urlparse(self.path).query)
                dst = req.get('dst',
                              ['0100::'])[0]  # Discard address by default
                size = req.get('sz', ['0'])[0]  # Zero size by default
                bash('ping -c1 -s%s %s' % (size, dst))
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


def start():
    global HTTPD, ANNOUNCER

    print('Loading web server...')
    while not HTTPD:
        # The port may have not been closed from the previous session
        # TODO: properly close server when stopping app
        try:
            HTTPD = socketserver.TCPServer(('', WEB_PORT), WebServer)
        except OSError:
            time.sleep(1)
    asyncio.get_event_loop().run_in_executor(None, HTTPD.serve_forever)
    print('Webserver is up.')

    # Announce via mDNS
    ANNOUNCER = zeroconf.Zeroconf()
    type_ = '_bbr._tcp.local.'
    name = 'Kirale-KiBRA %s' % int(time.time())
    props = {'ven': 'Kirale', 'mod': 'KiBRA', 'ver': KIBRA_VERSION}
    service = zeroconf.ServiceInfo(
        type_=type_,
        name='%s.%s' % (name, type_),
        port=WEB_PORT,
        properties=props)
    ANNOUNCER.register_service(service)
    print('%s service announced via mDNS' % name)


def stop():
    print('Stopping web server...')
    ANNOUNCER.close()
    HTTPD.server_close()
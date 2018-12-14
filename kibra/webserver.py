import asyncio
import http.server
import json
import logging
import os
import socketserver
import sys
import time
import xml.etree.ElementTree
import urllib

import kibra.database as db
from kibra.diags import DIAGS_DB
from kibra.ksh import bbr_dataset_update
from kibra.shell import bash

PUBLIC_DIR = os.path.dirname(sys.argv[0]) + '/public'
LEASES_PATH = '/var/lib/dibbler/server-AddrMgr.xml'


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

        if self.path.startswith('/api'):
            req = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
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
            if not set(['mlr_timeout', 'rereg_delay']).isdisjoint(modif_keys):
                bbr_dataset_update()
            data = 'OK'
        elif self.path.startswith('/ping'):
            req = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            dst = req.get('dst', ['0100::'])[0] # Discard address by default
            size = req.get('sz', ['0'])[0] # Zero size by default
            bash('ping -c1 -s%s %s' % (size, dst))
            data = 'OK'
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
    httpd = None
    logging.info('Loading web server...')
    while not httpd:
        # The port may have not been closed from the previous session
        # TODO: properly close server when stopping app
        try:
            httpd = socketserver.TCPServer(('', 80), WebServer)
        except OSError:
            time.sleep(1)
    asyncio.get_event_loop().run_in_executor(None, httpd.serve_forever)
    logging.info('Webserver is up.')

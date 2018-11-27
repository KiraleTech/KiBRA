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

PUBLIC_DIR = os.path.dirname(sys.argv[0]) + '/public'
LEASES_PATH = '/var/lib/dibbler/server-AddrMgr.xml'

KNONW_KEYS = [
    "action_coapserver", "action_dhcp", "action_diags", "action_dns",
    "action_mdns", "action_nat", "action_network", "action_serial",
    "autostart", "bagent_at", "bagent_cm", "bagent_port", "bbr_seq",
    "bbr_status", "bridging_mark", "bridging_table", "dhcp_pool",
    "dongle_channel", "dongle_commcred", "dongle_eid", "dongle_ll",
    "dongle_mac", "dongle_name", "dongle_netname", "dongle_panid",
    "dongle_prefix", "dongle_rloc", "dongle_role", "dongle_serial",
    "dongle_status", "dongle_xpanid", "exterior_ifname", "exterior_ifnumber",
    "exterior_ipv4", "exterior_port_mc", "interior_ifname",
    "interior_ifnumber", "interior_mac", "mcast_admin_fwd", "mlr_timeout",
    "pool4", "prefix", "rereg_delay", "serial_device", "status_coapserver",
    "status_dhcp", "status_diags", "status_dns", "status_mdns", "status_nat",
    "status_network", "status_serial"
]

MODIF_KEYS = [
    "action_coapserver", "action_dhcp", "action_diags", "action_dns",
    "action_mdns", "action_nat", "action_network", "action_serial",
    "autostart", "mlr_timeout", "rereg_delay"
]


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
    def do_POST(self):
        if not self.path.startswith('api'):
            return
        # TODO

    def do_GET(self):
        binary = False
        if self.path == '/':
            self.path = '/index.html'
        file_path = '%s%s' % (PUBLIC_DIR, self.path.replace('/assets', ''))
        mime_type = 'text/json'

        if self.path.startswith('/api'):
            req = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            for key in req.keys():
                if not key in MODIF_KEYS:
                    self.send_response(http.HTTPStatus.BAD_REQUEST)
                    return
            # Apply incoming changes
            for key, value in req.items():
                db.set(key, value[0])
            # Special actions
            if not set(["mlr_timeout", "rereg_delay"]).isdisjoint(
                    set(req.keys())):
                bbr_dataset_update()
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

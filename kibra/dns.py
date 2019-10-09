from time import sleep

import kibra.database as db
import kitools
from kibra.ktask import Ktask
from kibra.shell import bash

DNS_CONFIG = '/etc/unbound/unbound.conf'
DNS_DAEMON = 'unbound'


class DNS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='dns',
            start_keys=['ncp_mleid'],
            stop_keys=[],
            start_tasks=['network', 'serial', 'nat'],
            period=1,
        )

    def kstart(self):
        # Don't start if DHCP is not to be used
        if not db.get('prefix_dhcp'):
            return

        # Stop DNS daemon
        bash('service %s stop' % DNS_DAEMON)
        # Remove previous configuration
        db.del_from_file(DNS_CONFIG, '\nserver:', '\n    dns64-synthall: yes\n')
        # Add new configuration
        with open(DNS_CONFIG, 'w') as file_:
            file_.write('\nserver:')
            file_.write('\n    interface: %s' % db.get('ncp_mleid'))
            file_.write('\n    access-control: ::/0 allow')
            file_.write('\n    module-config: "dns64 validator iterator"')
            file_.write('\n    dns64-prefix: 64:ff9b::/96')
            file_.write('\n    dns64-synthall: yes\n')
        # Allow for the file to be stored
        sleep(0.2)
        # Start DNS daemon
        bash('service %s start' % DNS_DAEMON)

    def kstop(self):
        # Don't stop if DHCP is not to be used
        if not db.get('prefix_dhcp'):
            return

        # TODO: https://www.claudiokuenzler.com/blog/694/get-unbount-dns-lookups-resolution-working-ubuntu-16.04-xenial
        # Stop DNS daemon
        bash('service %s stop' % DNS_DAEMON)
        # Remove previous configuration for this NCP
        db.del_from_file(DNS_CONFIG, '\nserver:', '\n    dns64-synthall: yes\n')
        # Allow for the file to be stored
        sleep(0.2)
        # Start DNS daemon
        bash('service %s start' % DNS_DAEMON)

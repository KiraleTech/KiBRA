from time import sleep

import kitools

import kibra.database as db
from kibra.shell import bash
from kibra.ktask import Ktask

DNS_CONFIG = '/etc/unbound/unbound.conf'
DNS_DAEMON = 'unbound'


class DNS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='dns',
            start_keys=['dongle_eid'],
            stop_keys=[],
            start_tasks=['network', 'serial', 'nat'],
            period=1)

    def kstart(self):
        # Stop DNS daemon
        bash('service %s stop' % DNS_DAEMON)
        # Remove previous configuration
        db.del_from_file(DNS_CONFIG, '\nserver:','\n    dns64-synthall: yes\n')
        # Add new configuration
        with open(DNS_CONFIG, 'w') as file_:
            file_.write('\nserver:')
            file_.write('\n    interface: %s' % db.get('dongle_eid'))
            file_.write('\n    access-control: ::/0 allow')
            file_.write('\n    module-config: "dns64 validator iterator"')
            file_.write('\n    dns64-prefix: 64:ff9b::/96')
            file_.write('\n    dns64-synthall: yes\n')
        # Allow for the file to be stored
        sleep(0.2)
        # Start DNS daemon
        bash('service %s start' % DNS_DAEMON)

    def kstop(self):
        # Stop DNS daemon
        bash('service %s stop' % DNS_DAEMON)
        # Remove previous configuration for this dongle
        db.del_from_file(DNS_CONFIG, '\nserver:','\n    dns64-synthall: yes\n')
        # Allow for the file to be stored
        sleep(0.2)
        # Start DNS daemon
        bash('service %s start' % DNS_DAEMON)

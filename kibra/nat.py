import logging
import re

import kibra.database as db
import kibra.ksh as KSH
from kibra.shell import bash
from kibra.ktask import Ktask, status


def _nat_enable():
    bash('/sbin/modprobe jool')
    if 'default' not in str(bash('jool instance display')):
        bash('jool instance add --netfilter --pool6 64:ff9b::/96')
        bash('jool global update logging-session true')
        bash('jool global update logging-bib true')
    logging.info('Prefix 64:ff9b::/96 added to NAT64 engine.')
    bash('jool pool4 add --udp %s 10000-30000' % db.get('exterior_ipv4'))
    bash('jool pool4 add --icmp %s 10000-30000' % db.get('exterior_ipv4'))
    logging.info('%s used as stateful NAT64 masking address.',
                 db.get('exterior_ipv4'))
    KSH.prefix_handle('route', 'add', '64:ff9b::/96', stable=True)


def _nat_disable():
    KSH.prefix_handle('route', 'remove', '64:ff9b::/96', stable=True)
    if db.has_keys(['exterior_ipv4']):
        bash('jool pool4 remove --udp %s 10000-30000' %
             db.get('exterior_ipv4'))
        bash('jool pool4 remove --icmp %s' % db.get('exterior_ipv4'))
    bash('/sbin/modprobe -r jool')


class NAT(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='nat',
            start_keys=[],
            stop_keys=[],
            start_tasks=['serial'],
            period=3)
        self.nat_enabled = False

    async def periodic(self):
        # Launch NAT64 whenever the BBR is connected to an IPv4 network
        if not self.nat_enabled and db.has_keys(['exterior_ipv4']):
            _nat_enable()
            self.nat_enabled = True
        # Stop NAT64 whenever the BBR is disconnected from an IPv4 network
        elif self.nat_enabled and not db.has_keys(['exterior_ipv4']):
            _nat_disable()
            self.nat_enabled = False

    def kstop(self):
        if self.nat_enabled:
            _nat_disable()
            self.nat_enabled = False

    '''
    def check_status(self):
        logging.debug('Checking Jool status.')
        jool_status = bash('jool session display')
        try:
            jool_status = re.search(r'%s(.*)%s' % ('Status: ', '\n'),
                                    jool_status).group(1)
        except:
            jool_status = 'Stopped'
        if jool_status == 'Enabled':
            return status.RUNNING
        else:
            return status.STOPPED
    '''

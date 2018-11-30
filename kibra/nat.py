import logging
import re

import kibra.database as db
import kibra.ksh as KSH
from kibra.shell import bash
from kibra.ktask import Ktask, status


class NAT(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='nat',
            start_keys=[
                'exterior_ifname', 'exterior_ipv4', 'exterior_port_mc', 'pool4'
            ],
            stop_keys=['exterior_ipv4'],
            start_tasks=['serial'],
            period=3)

    def kstart(self):
        bash('/sbin/modprobe jool disabled')
        if '64:ff9b::/96' not in str(bash('jool --pool6')):
            bash('jool --pool6 --add 64:ff9b::/96')
        logging.info('Prefix 64:ff9b::/96 added to NAT64 engine.')
        if db.has_keys(['exterior_ipv4']):
            bash('jool --pool4 --add --udp %s 10000-30000' %
                 db.get('exterior_ipv4'))
            bash('jool --pool4 --add --icmp %s' % db.get('exterior_ipv4'))
            logging.info('%s used as stateful NAT64 masking address.',
                         db.get('exterior_ipv4'))
        bash('jool --enable')
        KSH.prefix_handle('route', 'add', '64:ff9b::/96', stable=True)

    def kstop(self):
        KSH.prefix_handle('route', 'remove', '64:ff9b::/96', stable=True)
        bash('/sbin/modprobe jool disabled')
        if db.has_keys(['exterior_ipv4']):
            bash('jool --pool4 --remove --udp %s 10000-30000' %
                 db.get('exterior_ipv4'))
            bash('jool --pool4 --remove --icmp %s' % db.get('exterior_ipv4'))
        bash('jool --enable')

    def check_status(self):
        logging.debug('Checking Jool status.')
        jool_status = bash('jool')
        try:
            jool_status = re.search(r'%s(.*)%s' % ('Status: ', '\n'),
                                    jool_status).group(1)
        except:
            jool_status = 'Stopped'
        if jool_status == 'Enabled':
            return status.RUNNING
        else:
            return status.STOPPED

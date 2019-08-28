import ipaddress
import logging
import re

import kibra.database as db
from kibra.ktask import Ktask, status
from kibra.shell import bash

POOL4_ACTIVE = None


def _nat_enable():
    global POOL4_ACTIVE

    bash('/sbin/modprobe jool')
    POOL4_ACTIVE = False
    logging.info('NAT64 engine started.')

    if 'default' not in str(bash('jool instance display')):
        bash('jool instance add --netfilter --pool6 64:ff9b::/96')
        bash('jool global update logging-session true')
        bash('jool global update logging-bib true')
    logging.info('Prefix 64:ff9b::/96 added to NAT64 engine.')


def _nat_disable():
    bash('/sbin/modprobe -r jool')
    logging.info('NAT64 engine stopped.')


def handle_nat64_masking(ext_addr, enable=True):
    '''Enable or disable one exterior IPv4 address in the NAT64 Pool 4'''
    global POOL4_ACTIVE

    # Don't allow IPv6 addresses here
    try:
        ipaddress.IPv4Address(ext_addr)
    except:
        return

    jool_action = 'add' if enable else 'remove'
    log_action = 'used' if enable else 'removed'

    # Only allow one address in the Pool 4
    if (enable and POOL4_ACTIVE) or (not enable and not POOL4_ACTIVE):
        logging.info(
            'Unable to %s %s as stateful NAT64 masking address.', jool_action, ext_addr
        )
        return

    params = (jool_action, ext_addr)
    bash('jool pool4 %s --udp %s' % params)
    bash('jool pool4 %s --icmp %s' % params)
    POOL4_ACTIVE = True

    logging.info('%s %s as stateful NAT64 masking address.', ext_addr, log_action)


class NAT(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='nat',
            start_keys=[],
            stop_keys=[],
            start_tasks=['serial'],
            period=1,
        )

    def kstart(self):
        _nat_enable()

    def kstop(self):
        _nat_disable()

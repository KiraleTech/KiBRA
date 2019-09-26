import ipaddress
import logging

import kibra.database as db
from kibra.shell import bash
from kibra.thread import DEFS

# TODO: use http://ldx.github.io/python-iptables/


def handle_ipv6(action):
    '''handle_ipv6('A')  --> Add the rules
    handle_ipv6('D')  --> Delete the rules'''

    if action is 'A':
        logging.info('Adding ip6tables general rules.')
        # This should not be needed if KiBRA was closed correctly
        bash('ip6tables -F -t mangle')
        bash('ip6tables -F -t nat')
        bash('ip6tables -F -t filter')
    elif action is 'D':
        logging.info('Deleting ip6tables general rules.')
    else:
        return

    interior_ifname = db.get('interior_ifname')

    # INPUT
    # Disallow incoming multicast ping requests
    bash(
        'ip6tables -w -t filter -%s INPUT -i %s -d ff00::/8 -p icmpv6 --icmpv6-type echo-request -j DROP'
        % (action, db.get('exterior_ifname'))
    )

    # OUTPUT
    # Prevent fragmentation
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -m length --length 1281:0xffff -j REJECT'
        % (action, interior_ifname)
    )
    # Allow some ICMPv6 traffic towards the Thread interface
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT'
        % (action, interior_ifname)
    )
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p icmpv6 --icmpv6-type echo-request -j ACCEPT'
        % (action, interior_ifname)
    )
    # Allow CoAP
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p udp --sport %s -j ACCEPT'
        % (action, interior_ifname, DEFS.PORT_COAP)
    )
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p udp --dport %s -j ACCEPT'
        % (action, interior_ifname, DEFS.PORT_COAP)
    )
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p udp --sport %s -j ACCEPT'
        % (action, interior_ifname, DEFS.PORT_MM)
    )
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p udp --dport %s -j ACCEPT'
        % (action, interior_ifname, DEFS.PORT_MM)
    )
    # Allow DHCPv6 server
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p udp --dport dhcpv6-client -j ACCEPT'
        % (action, interior_ifname)
    )
    # Allow NTP server
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p udp --sport 123 -j ACCEPT'
        % (action, interior_ifname)
    )
    # Allow DNS server
    bash(
        'ip6tables -w -t filter -%s OUTPUT -o %s -p udp --sport 53 -j ACCEPT'
        % (action, interior_ifname)
    )
    # Block all other outgoing traffic to the Thread interface
    bash('ip6tables -w -t filter -%s OUTPUT -o %s -j DROP' % (action, interior_ifname))
    # Block Thread traffic on the Ethernet interface
    if not db.get('prefix_dua'):
        bash(
            'ip6tables -w -t filter -%s OUTPUT -o %s -p ipv6 -d %s -j DROP'
            % (action, db.get('exterior_ifname'), db.get('prefix'))
        )

    # FORWARD
    # Prevent fragmentation
    bash(
        'ip6tables -w -t filter -%s FORWARD -o %s -m length --length 1281:0xffff -j REJECT'
        % (action, interior_ifname)
    )
    # Forward marked packets for PBR
    bash(
        'ip6tables -w -t filter -%s FORWARD -m mark --mark "%s" -j ACCEPT'
        % (action, db.get('bridging_mark'))
    )
    # Forward ping
    bash(
        'ip6tables -w -t filter -%s FORWARD -p icmpv6 --icmpv6-type echo-request -d %s -j ACCEPT'
        % (action, db.get('prefix'))
    )
    bash(
        'ip6tables -w -t filter -%s FORWARD -p icmpv6 --icmpv6-type echo-reply -s %s -j ACCEPT'
        % (action, db.get('prefix'))
    )
    # Reflective session state (9.2.7_13)
    bash(
        'ip6tables -w -t filter -%s FORWARD -p udp -m state --state ESTABLISHED -j ACCEPT'
        % (action)
    )
    bash(
        'ip6tables -w -t filter -%s FORWARD -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT'
        % (action)
    )
    '''
    # Forward multicast (filtering is made by mcrouter)
    bash('ip6tables -w -t mangle -%s PREROUTING -d ff00::/8 -j HL --hl-inc 1' % (action))
    '''
    # Block all other forwarding to the Thread interface
    bash(
        'ip6tables -w -t filter -%s FORWARD -d %s -j DROP' % (action, db.get('prefix'))
    )


def _handle_ipv4(action):
    '''
    Block most of the exterior traffic
     _handle_ipv4('A')  --> Add the rules
     _handle_ipv4('D')  --> Delete the rules
    '''
    if action == 'A':
        # This should not be needed if KiBRA was closed correctly
        bash('iptables -F -t mangle')

    exterior_ifname = db.get('exterior_ifname')

    bash(
        'iptables -w -t filter -%s INPUT -i %s -p icmp -j ACCEPT'
        % (action, exterior_ifname)
    )
    bash(
        'iptables -w -t filter -%s INPUT -i %s -p udp --dport mdns -j ACCEPT'
        % (action, exterior_ifname)
    )
    bash(
        'iptables -w -t filter -%s INPUT -i %s -p udp --dport dhcpv6-client -j ACCEPT'
        % (action, exterior_ifname)
    )
    bash(
        'iptables -w -t filter -%s INPUT -i %s -m state --state ESTABLISHED,RELATED -j ACCEPT'
        % (action, exterior_ifname)
    )
    bash('iptables -w -t filter -%s INPUT -i %s -j DROP' % (action, exterior_ifname))


def handle_diag(action, ncp_rloc):
    '''handle_diag('I') -> Insert the rules
    diagNetfilter('D') -> Delete the rules'''
    if action is 'I':
        logging.info('Redirecting MM port traffic to interior interface.')
    elif action is 'D':
        logging.info('Deleting ip6tables diagnostics rules.')
    else:
        return

    bash(
        'ip6tables -w -t mangle -%s OUTPUT -o lo -d %s -p udp --dport %s -j MARK --set-mark "%s"'
        % (action, ncp_rloc, DEFS.PORT_MM, db.get('bridging_mark'))
    )


def block_local_multicast(action, maddr):
    src = db.get('exterior_ipv6_ll')
    if action is 'I':
        logging.info('Blocking local traffic to %s' % maddr)
    elif action is 'D':
        logging.info('Unblocking local traffic to %s' % maddr)
    else:
        return
    bash('ip6tables -w -t filter -%s INPUT -s %s -d %s -j DROP' % (action, src, maddr))


def handle_bagent_fwd(ext_addr, int_addr, enable=True):
    '''Enable or disable Border Agent traffic forwarding between one exterior 
    address and the NCP, using Jool for IPv6 and iptables for IPv6'''

    # Get parameters
    try:
        ipaddress.IPv4Address(ext_addr)
        is_ipv4 = True
    except:
        is_ipv4 = False
    jool_action = 'add' if enable else 'remove'
    ipt_action = 'I' if enable else 'D'
    ipt_bin = 'iptables' if is_ipv4 else 'ip6tables'
    ext_ifame = db.get('exterior_ifname')
    ext_port = db.get('exterior_port_mc')
    int_port = db.get('bagent_port')
    brdg_mark = db.get('bridging_mark')

    # NAT 4 -> 6
    if is_ipv4:
        params = (jool_action, ext_addr, ext_port, int_addr, int_port)
        bash('jool bib %s %s#%s %s#%s --udp' % params)
    # NAT 6 -> 6
    else:
        params = (ipt_action, ext_ifame, ext_addr, ext_port, int_addr, int_port)
        bash(
            'ip6tables -w -t nat -%s PREROUTING -i %s -d %s -p udp --dport %d -j DNAT --to [%s]:%d'
            % params
        )

    # Mark MC packets before they are translated, so they are not consumed by Linux but by the dongle
    params = (ipt_bin, ipt_action, ext_ifame, ext_addr, ext_port, brdg_mark)
    bash(
        '%s -w -t mangle -%s PREROUTING -i %s -d %s -p udp --dport %d -j MARK --set-mark %s'
        % params
    )

    logging.info('Border Agent forwarding updated.')

import logging

import kibra.database as db
from kibra.shell import bash

# TODO: use http://ldx.github.io/python-iptables/


def handle_ipv6(action):
    '''handle_ipv6('A')  --> Add the rules
    handle_ipv6('D')  --> Delete the rules'''
    if action is 'A':
        logging.info('Adding ip6tables general rules.')
        # This should not be needed if KiBRA was closed correctly
        bash('ip6tables -F -t filter')
        bash('ip6tables -F -t mangle')
    elif action is 'D':
        logging.info('Deleting ip6tables general rules.')
    else:
        return

    ## Filter rules ##
    # Prevent fragmentation
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' + db.get(
        'interior_ifname') + ' -m length --length 1281:0xffff -j REJECT')
    # Allow some ICMPv6 traffic towards the Thread interface
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') +
         ' -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT')
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' + db.get(
        'interior_ifname') + ' -p icmpv6 --icmpv6-type echo-request -j ACCEPT')
    # Allow CoAP
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') + ' -p udp --sport 5683 -j ACCEPT')
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') + ' -p udp --dport 5683 -j ACCEPT')
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') + ' -p udp --dport 61631 -j ACCEPT')
    # Allow DHCPv6 server
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') + ' -p udp --dport dhcpv6-client -j ACCEPT')
    # Allow NTP server
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') + ' -p udp --sport 123 -j ACCEPT')
    # Allow DNS server
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') + ' -p udp --sport 53 -j ACCEPT')
    # Allow IPv6 traffic towards the global Thread network
    # bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
    # db.get('interior_ifname') + ' -p ipv6 -d ' +
    # db.get('dhcp_pool').split('/')[0] + ' -j ACCEPT')
    # Block all other outgoing traffic to the Thread interface
    bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
         db.get('interior_ifname') + ' -j DROP')
    # Block Thread traffic on the Ethernet interface
    if 'dhcp_pool' in db.CFG:
        bash('ip6tables -w -t filter -' + action + ' OUTPUT -o ' +
             db.get('exterior_ifname') + ' -p ipv6 -d ' +
             db.get('dhcp_pool').split('/')[0] + ' -j DROP')

    # Prevent fragmentation
    bash('ip6tables -w -t filter -' + action + ' FORWARD -o ' + db.get(
        'interior_ifname') + ' -m length --length 1281:0xffff -j REJECT')
    # Forward marked packets for PBR
    bash('ip6tables -w -t filter -' + action + ' FORWARD -m mark --mark "' +
         str(db.get('bridging_mark')) + '" -j ACCEPT')
    # Forward ping
    if 'dhcp_pool' in db.CFG:
        bash('ip6tables -w -t filter -' + action +
             ' FORWARD -p icmpv6 --icmpv6-type echo-request -d ' +
             db.get('dhcp_pool').split('/')[0] + ' -j ACCEPT')
        bash('ip6tables -w -t filter -' + action +
             ' FORWARD -p icmpv6 --icmpv6-type echo-reply -s ' +
             db.get('dhcp_pool').split('/')[0] + ' -j ACCEPT')
    # Reflective session state (9.2.7_13)
    bash('ip6tables -w -t filter -' + action +
         ' FORWARD -p udp -m state --state ESTABLISHED -j ACCEPT')
    bash('ip6tables -w -t filter -' + action +
         ' FORWARD -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT')
    # Block all other forwarding to the Thread interface
    if 'dhcp_pool' in db.CFG:
        bash('ip6tables -w -t filter -' + action + ' FORWARD -d ' +
             db.get('dhcp_pool').split('/')[0] + ' -j DROP')


def _handle_ipv4(action):
    '''
    Block most of the exterior traffic
     _handle_ipv4('A')  --> Add the rules
     _handle_ipv4('D')  --> Delete the rules
    '''
    if action == 'A':
        # This should not be needed if KiBRA was closed correctly
        bash('iptables -F -t mangle')
    bash('iptables -w -t filter -' + action + ' INPUT -i ' +
         db.get('exterior_ifname') + ' -p icmp -j ACCEPT')
    bash('iptables -w -t filter -' + action + ' INPUT -i ' +
         db.get('exterior_ifname') + ' -p udp --dport mdns -j ACCEPT')
    bash('iptables -w -t filter -' + action + ' INPUT -i ' +
         db.get('exterior_ifname') + ' -p udp --dport dhcpv6-client -j ACCEPT')
    bash('iptables -w -t filter -' + action + ' INPUT -i ' + db.get(
        'exterior_ifname') + ' -m state --state ESTABLISHED,RELATED -j ACCEPT')
    bash('iptables -w -t filter -' + action + ' INPUT -i ' +
         db.get('exterior_ifname') + ' -j DROP')


def handle_diag(action):
    '''handle_diag('I') -> Insert the rules
    diagNetfilter('D') -> Delete the rules'''
    if action is 'I':
        logging.info('Redirecting MM port traffic to interior interface.')
    elif action is 'D':
        logging.info('Deleting ip6tables diagnostics rules.')
    else:
        return
    bash('ip6tables -w -t mangle -' + action + ' OUTPUT -o lo -d ' +
         db.get('dongle_rloc') + ' -p udp --dport 61631 -j MARK --set-mark "'
         + str(db.get('bridging_mark')) + '"')

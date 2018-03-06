import logging
import socket

import kibra.database as db
from kibra.shell import bash
from kibra.ktask import Ktask

mdns_config = "/etc/avahi/avahi-daemon.conf"
mdns_hosts = "/etc/avahi/hosts"
mdns_daemon = "/etc/init.d/avahi-daemon"
vendor_name = "KiraleTechnologies"
device_name = "KiraleBR"

# natMdnsStart I -> Insert the rules ; natMdnsStart D -> Delete the rules


def nat_start(action):
    # NAT 4 -> 6
    if db.has_keys(['exterior_ipv4']):
        if action == 'I':
            bash(
                'jool --bib --add --udp ' + db.get('exterior_ipv4') + '#' +
                str(db.get('exterior_port_mc')) + ' ' + db.get('dongle_rloc')
                + '#' + str(db.get('bagent_port')) + ' &> /dev/null')
        else:
            bash(
                'jool --bib --remove --udp ' + db.get('exterior_ipv4') + '#' +
                str(db.get('exterior_port_mc')) + ' ' + db.get('dongle_rloc')
                + '#' + str(db.get('bagent_port')) + ' &> /dev/null')
        # Mark MC packets before they are translated, so they are not consumed by Linux but by the dongle
        bash(
            'iptables -w -t mangle -%s PREROUTING -i %s -d %s -p udp --dport %d -j MARK --set-mark %s'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv4'),
               db.get('exterior_port_mc'), db.get('bridging_mark')))
    # NAT 6 -> 6
    if db.has_keys(['exterior_ipv6']):
        bash(
            'ip6tables -w -t nat -%s PREROUTING -i %s -d %s -p udp --dport %d -j DNAT --to [%s]:%d'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv6'),
               db.get('exterior_port_mc'), db.get('dongle_rloc'),
               db.get('bagent_port')))
        bash(
            'ip6tables -w -t nat -%s POSTROUTING -o %s -s %s -p udp --sport %d -j SNAT --to [%s]:%d'
            % (action, db.get('exterior_ifname'), db.get('dongle_rloc'),
               db.get('bagent_port'), db.get('exterior_ipv6'),
               db.get('exterior_port_mc')))
        bash(
            'ip6tables -w -t mangle -%s PREROUTING -i %s -d %s -p udp --dport %d -j MARK --set-mark %s'
            % (action, db.get('exterior_ifname'), db.get('exterior_ipv6'),
               db.get('exterior_port_mc'), db.get('bridging_mark')))


class MDNS(Ktask):
    def __init__(self):
        Ktask.__init__(
            self,
            name='mdns',
            start_keys=[
                'exterior_ifname', 'exterior_ipv4', 'dongle_netname',
                'dongle_xpanid'
            ],
            stop_keys=['interior_ifname'],
            # Needs diags to have the latest xpanid
            start_tasks=['diags', 'network'],
            period=5)

    def kstart(self):
        logging.info('Configuring Avahi daemon.')
        with open(mdns_config, 'w') as file_:
            file_.write('[server]\n')
            file_.write('use-ipv4=%s\n' %
                        ('yes' if db.has_keys(['exterior_ipv4']) else 'no'))
            file_.write('use-ipv6=%s\n' %
                        ('yes' if db.has_keys(['exterior_ipv6']) else 'no'))
            file_.write('allow-interfaces=%s\n' % db.get('exterior_ifname'))
            file_.write('disallow-other-stacks=yes\n\n')
            file_.write('[publish]\n')
            file_.write('publish-addresses=yes\n')
            file_.write('publish-hinfo=no\n')
            file_.write('publish-workstation=no\n')
            file_.write('publish-domain=no\n')
            file_.write('publish-aaaa-on-ipv4=no\n')
            file_.write('publish-a-on-ipv6=no\n\n')
            file_.write('[rlimits]\n')
            file_.write('rlimit-core=0\n')
            file_.write('rlimit-data=4194304\n')
            file_.write('rlimit-fsize=0\n')
            file_.write('rlimit-nofile=30\n')
            file_.write('rlimit-stack=4194304\n')
            file_.write('rlimit-nproc=3\n')

        # Add host

    #  with open(mdns_hosts, 'r+') as file_:
    #    oldFile = file_.readlines()
    #    file_.seek(0)
    #    file_.truncate()
    #    for line in oldFile:
    #      if socket.gethostname() not in line:
    #        file_.write(line)
    #    if 'exterior_ipv4' in db.CFG:
    #      file_.write('%s %s.local\n' % (db.get('exterior_ipv4'), socket.gethostname()))
    #    if 'exterior_ipv6' in db.CFG:
    #      file_.write('%s %s.local\n' % (db.get('exterior_ipv6'), socket.gethostname()))

    # Enable service
        logging.info('Adding Avahi service.')
        with open('/etc/avahi/services/' + db.get('dongle_name') + '.service',
                  'w') as file_:
            file_.write(
                '<?xml version="1.0" encoding="utf-8" standalone="no"?>\n')
            file_.write(
                '<!DOCTYPE service-group SYSTEM "avahi-service.dtd">\n')
            file_.write('<service-group>\n')
            file_.write('  <name>%s %s %s</name>\n' %
                        (db.get('dongle_name'), vendor_name, device_name))
            file_.write('  <service>\n')
            file_.write('      <type>_meshcop._udp</type>\n')
            file_.write('      <host-name>%s.local</host-name>\n' %
                        socket.gethostname())
            file_.write('      <port>%d</port>\n' % db.get('exterior_port_mc'))
            file_.write('      <txt-record>rv=%s</txt-record>\n' % '1')
            file_.write('      <txt-record>tv=%s</txt-record>\n' % '1.1.0')
            file_.write(
                '      <txt-record value-format="binary-hex">sb=%s</txt-record>\n'
                % '00000082')
            file_.write('      <txt-record>nn=%s</txt-record>\n' %
                        db.get('dongle_netname'))
            file_.write(
                '      <txt-record value-format="binary-hex">xp=%s</txt-record>\n'
                % db.get('dongle_xpanid').replace('0x', ''))
            file_.write('      <txt-record>vn=%s</txt-record>\n' % vendor_name)
            file_.write('      <txt-record>mn=%s</txt-record>\n' % device_name)
            file_.write('  </service>\n')
            file_.write('</service-group>\n')

        # Restart daemon
        logging.info('Reloading Avahi daemon.')
        bash('systemctl daemon-reload')
        bash(mdns_daemon + ' restart > /dev/null')

        # Enable NAT
        logging.info('Enabling Border Agent NAT.')
        nat_start('I')

    def kstop(self):
        # Disnable NAT
        logging.info('Disabling Border Agent NAT.')
        nat_start('D')

        # Disable service
        logging.info('Removing Avahi service.')
        bash('rm /etc/avahi/services/' + db.get('dongle_name') + '.service')

        # Restart daemon
        logging.info('Reloading Avahi daemon.')
        bash('systemctl daemon-reload')
        bash(mdns_daemon + ' restart')

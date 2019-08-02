===========================================
Kirale Border Router Administration (KiBRA)
===========================================

This project intends to be a reference implementation of a `Thread
<https://www.threadgroup.org/>`_ 1.2 Backbone Border Router for a `GNU/Linux Debian
<https://www.debian.org/>`_ host and a `KiNOS <http://kinos.io/>`_ USB enabled
device.

It is written in Python 3, and provides a fast way for third-party developers
to test they Thread products´ site and global connectivity, or an starting
point for a commercial Border Router implementation.

This project is licensed under the terms of the MIT license.

.. contents:: :local:

Features
========

- Thread Domains support.
- Multicast forwarding support.
- DHCPv6 server (`Dibbler <http://klub.com.pl/dhcpv6/>`_) autoconfiguration for
  DHCPv6-PD or ULA prefixes.
- NTP client and server, advertised to the Thread network in the DHCP options.
- Stateful NAT64 (`Jool <https://www.jool.mx/>`_) autoconfguration.
- DNS64 server (`Unbound <http://www.unbound.net/>`_).
- mDNS (`Python Zeroconf <https://github.com/jstasiak/python-zeroconf>`_) 
  advertisement of MeshCoP Border Agent service in the exterior network, with 
  support for external commissioner.
- Thread network real-time supervision with Thread Management Framework using a
  CoAP client (`aiocoap <https://www.avahi.org/>`_).
- Web based dynamic network visualization.
- Includes a tool to easyly form a big test Thread network with other attached
  KiNOS devices.

  .. image:: images/KiBRA-Web.png

Future improvements
===================

- `Port Control Protocol <https://datatracker.ietf.org/wg/pcp/documents/>`_
- Web based network configuration and commissioning.
- Multi-Thread interface support.

Requirements
============

The KiBRA application requires a `Python <https://python.org>`_ 3.7 installation
and makes use of several PyPI modules, apart from the `KiTools
<https://github.com/KiraleTechnologies/KiTools>`_ module. It has been tested in
Debian Buster and Raspbian Buster systems, but it will probably run correctly
in many other GNU/Linux distributions.

The required system packages are: ``avahi-daemon``, ``dibbler-server``, 
``iproute2``, ``ip6tables``, ``jool``, ``nmap``, ``ntp``, ``radvd`` and 
``unbound``.

The required Python modules are: ``aiocoap-kirale``, ``bash``, ``daemonize``,
``kitools`` and ``pyroute2``.

Installation
============

Install and configure system packages.
::

 apt install avahi-daemon dibbler-server ntp radvd unbound virtualenv -y
 echo "" > /etc/dibbler/server.conf

There is no official Debian package for Jool yet, so it needs to be built as
explained in the `Jool packaging repository
<https://github.com/ydahhrk/packaging/tree/master/Jool>`_ and later installed:
::

 apt install jool-dkms_*.deb jool-tools_*.deb -y
 apt install /tmp/overlay/kibra/deb/jool-tools_4.0.3-1_armhf.deb

Enable a virtual environment for the Python installation.
::

 apt install virtualenv
 python3 -m virtualenv -p /usr/bin/python3 /opt/kirale/pyenv
 source /opt/kirale/pyenv/bin/activate

Download and install KiTools, aiocoap and KiBRA. The required Python modules 
will be auto-installed.
::

 git clone https://github.com/KiraleTech/KiTools.git
 cd KiTools
 python -m pip install --upgrade .
 cd ..
 git clone https://github.com/KiraleTech/aiocoap.git
 cd aiocoap
 git checkout kirale-1.0
 python -m pip install --upgrade .
 cd ..
 git clone https://github.com/KiraleTech/KiBRA.git
 cd KiBRA
 python -m pip install --upgrade .
 cd ..


''systemd'' integration
-----------------------

This will make KiBRA run at startup, as soon as system network is enabled:
::

 cp systemd/kibra.sh /opt/kirale/
 cp systemd/kibra.service /etc/systemd/system/
 systemctl enable kibra.service


Usage
=====

Plug a `KTDG102 USB <https://www.kirale.com/products/ktdg102/>`_ dongle in (not
needed if using a KTBRN1) and run the installed script in the virtual
environment:
::

 python -m kibra

If everything goes well, the script is going to detect the exterior interface
and the connected dongle, and configure the interfaces accordingly. If the
dongle USB Ethernet is not enabled, it is enabled by the script. By default,
the KiNOS device will perform an energy scan to select a proper IEEE 802.15.4
channel and start a Thread network partition on it as Leader.

Once the interior interface is up, the routing and firewall is configured and
the services launched: DHCP, NAT and DNS for the interior interface, and mDNS
for the exterior interface. Also the TMF subsystem starts to query the dongle
for network information. With this information, the network visualization can be
drawn. Open a browser on the exterior interface address to see it. Once more
nodes are added to the network, the topology and link qualities will be
updated.

To stop the script, just type ``Ctrl+C`` and wait until all tasks have been
stopped.

Configuration file
------------------

The configuration file for the Kirale Border Router is located in
``/opt/kirale/kibra.cfg`` and has JSON format. If not provided, it is created
automatically at the first start with default values:
::

 {
   "dongle_name": "Test",
   "dongle_commcred": "KIRALE"
 }

The user can also force some other configuration options:
::

 {
   "dongle_channel": 20,
   "dongle_commcred": "KIRALE",
   "dongle_name": "MyDongle",
   "dongle_netname": "MyNetwork",
   "dongle_panid": "0xc04b",
   "dongle_role": "leader",
   "dongle_serial": "KTWM102-11+201801+8404D2000000045C"
   "exterior_ifname": "eth00",
   "prefix": "2017:0:0:5::/64"
 }

Network formation
-----------------

The Kirale Border Router acts as a Border Agent for external commissioners. The
`Thread Commissioning App
<https://play.google.com/store/apps/details?id=org.threadgroup.commissioner>`_
can be installed in an Android device and connected to a Wi-Fi access point in
the same network as the Border Router.

If KiBRA was started correctly, the Commissioning App should be able to
discover the advertised network and ask for the Commissioner Credential in
order to access to its management. Once entered (by default: "KIRALE") it
should successfully join to the network and allow to scan a QR code.

    Tip: Use ``tcpdump`` for traffic overview on the interior interface.

Scan the QR code from another KTDG102 USB Dongle enclosure label and it will be
added to the Commissioner App entitled joiners list. The only configuration
required for the joiner is its desired role, and afterwards it can be booted in
the network.
::

 config role med
 ifup

The joiner should complete the commissioning with the Commissioning App and
appear in the network visualization. To check the correct border Router
functioning, enable the debug logs and send a ping request to an Inernet
address:
::

 debug module ipv6 icmp
 debug level all
 ping "kirale.com"

An ICMP echo response should arrive to the joined device.

Automatic network formation
---------------------------

The KiBRA application can be executed (from another terminal) with the
``--form`` option to read the currently running Border Router network
credentials and apply them to any plugged-in KTDG102 USB Dongles. Once
configured the devices join to the network in out-of-band mode, avoiding the
slow commissioning process.

This allows a fast network formation for different testing purposes.

The ``--clear`` option can be used to clear the configuration of all attached
KTDG102 USB Dongles, and therefore, remove them from the network.

Armbian Image
====================================

It is possible to access to use a serial terminal throught the USB port to 
access to the system shell. The default credentials are:

:User: ``root``
:Password: ``kirale123``

You may want to configure keyboard and time zone:
::

 dpkg-reconfigure tzdata
 dpkg-reconfigure ntp
 dpkg-reconfigure keyboard-configuration
 setupcon

The SSH server is enabled by default, and the preset Ethernet IPv4 address is
192.168.75.84.

===========================================
Kirale Border Router Administration (KiBRA)
===========================================

This project intends to be a reference implementation of a `Thread
<https://www.threadgroup.org/>`_ Border Router for a `GNU/Linux Debian
<https://www.debian.org/>`_ host and a `KiNOS <http://kinos.io/>`_ USB enabled
device.

It is written in Python 3.6, and provides a fast way for third-party developers
to test they Thread products´ site and global connectivity, or an starting
point for a commercial Border Router implementation.

Although it of course runs in single-board computers like `Raspberry Pi
<https://www.raspberrypi.org/>`_ or `Beagle Board <https://beagleboard.org/>`_,
there is not even need to purchase any additional hardware apart from a
`KTDG102 USB Dongle <https://www.kirale.com/products/ktdg102/>`_ thanks to the
provided Virtual Machine Image Disk which can be run in any modern computer.

This project is licensed under the terms of the MIT license.

.. contents:: :local:

Features
========

- Autodetects an attached KiNOS device and uses it as Thread interface.
- Autodetects the exterior interface configuration (default route), but it is
  also possible to manually set the configuration.
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

The KiBRA application requires a `Python <https://python.org>`_ 3.6 installation
and makes use of several PyPI modules, apart from the `KiTools
<https://github.com/KiraleTechnologies/KiTools>`_ module. It has been tested in
Debian Buster and Raspbian Buster systems, but it will probably run correctly
in many other GNU/Linux distributions.

The required system packages are: ``dibbler-server``, ``iproute2``,
``ip6tables``, ``jool``, ``ntp`` and ``unbound``.

The required Python modules are: ``aiocoap``, ``bash``, ``kitools``,
``pycryptodomex``, ``pyroute2`` and ``zeroconf``.

Installation
============

Install and configure system packages.
::

 apt install git python3 python3-pip avahi-daemon dibbler-server ntp unbound
 echo "" > /etc/dibbler/server.conf

There is no official Debian package for Jool yet, so it needs to be compiled
from sources.
::

 cd
 apt install gcc make pkg-config libnl-genl-3-dev autoconf dkms linux-headers-$(uname -r) debhelper
 wget https://github.com/NICMx/releases/raw/master/Jool/Jool-3.5.7.zip
 unzip Jool-3.5.7.zip
 dkms install Jool-3.5.7
 cd Jool-3.5.7/usr
 bash autogen.sh && ./configure && make && make install
 cd && rm Jool-3.5.7.zip

Enable a virtual environment for the Python installation.
::

 apt install virtualenv
 python3 -m virtualenv -p /usr/bin/python3 /opt/kirale/pyenv
 source /opt/kirale/pyenv/bin/activate

Download and install KiTools and KiBRA. The required Python modules will be
auto-installed.
::

 git clone https://github.com/KiraleTech/KiTools.git
 cd KiTools
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

Plug a `KTDG102 USB <https://www.kirale.com/products/ktdg102/>`_ dongle in and
run the installed script in the virtual environment:
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
   "exterior_ifname": "wlan0",
   "pool4": "10.92.0.0/16",
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

Kirale Border Router Virtual Machine
====================================

As a fast way for evaluating the KiNOS devices Thread Border Router
capabilities, a `Virtual Appliance` is provided ready for usage in a virtual
machine environment (`VirtualBox <https://www.virtualbox.org/>`_, `VMWare 
<https://www.vmware.com/>`_...).

⬇⬇⬇ `Kirale-Thread-Border-Router.ova
<https://drive.google.com/open?id=1ularXx5a-T1iw3Xzc1AkosugqHFkgt5u>`_ ⬇⬇⬇

The image is based on Debian Buster and has the required dependancies installed.

Usage in VirtualBox 5.2.8
-------------------------

From the VirtualBox main screen go to ``File → Import appliance...``, find the
downloaded file and import it. A new virtual machine will appear in the list and
can be started. Make sure a network adapter is enabled as *Bridged adapter*
under ``Network`` settings, and *USB 2.0* is enabled.

The default credentials are:

:User: ``root``
:Password: ``kirale``

You may want to configure keyboard and time zone:
::

 dpkg-reconfigure tzdata
 dpkg-reconfigure keyboard-configuration
 setupcon

The SSH server is enabled by default, in case it is necessary to access the 
virtual machine from a remote location. Just take note of the DHCP obtained
address(es) via the virtual netkork adapter:
::

 ip addr

The Python virtual environment is located in ``/root/py36env/`` and contains
clones from the KiTools and KiBRA repositories. You may want to update them for
last changes:
::

 cd /root/py36env
 source bin/activate
 cd KiTools
 git pull origin master
 python -m pip install --upgrade .
 cd /root/py36env/KiBRA
 git pull origin master
 python -m pip install --upgrade .

At this point, plug in a KTDG102 USB Dongle to a USB port from the host machine
and capture it for the virtual machine: right click on the bottom USB icon and
click on ``Kirale Technologies KTWM102 Module``. Check that the guest machine
adquired it:
::

 dmesg | tail -n 12
 [   91.616127] usb 2-2: new full-speed USB device number 3 using ohci-pci
 [   91.966133] usb 2-2: New USB device found, idVendor=2def, idProduct=0102
 [   91.966142] usb 2-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
 [   91.966147] usb 2-2: Product: KTWM102 Module
 [   91.966153] usb 2-2: Manufacturer: Kirale Technologies
 [   91.966158] usb 2-2: SerialNumber: 8404D2000000045C
 [   92.059395] cdc_ether 2-2:1.3 eth0: register 'cdc_ether' at usb-0000:00:06.0-2, CDC Ethernet Device, 84:04:d2:00:04:5c
 [   92.059641] cdc_acm 2-2:1.1: ttyACM0: USB ACM device
 [   92.060069] usbcore: registered new interface driver cdc_ether
 [   92.066109] usbcore: registered new interface driver cdc_acm
 [   92.066111] cdc_acm: USB Abstract Control Model driver for USB modems and ISDN adapters
 [   92.077118] cdc_ether 2-2:1.3 enx8404d200045c: renamed from eth0

Now it is possible to run the KiBRA application:
::

 python -m kibra

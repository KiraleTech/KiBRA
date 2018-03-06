$.get("http://" + window.location.hostname + "/db/cfg", function (data) {
  $('form').jsonForm({
    schema: {
      action_dhcp: {
        type: 'string',
        title: 'Action DHCPv6',
        enum: ['none', 'start', 'stop']
      },
      action_mdns: {
        type: 'string',
        title: 'Action mDNS',
        enum: ['none', 'start', 'stop']
      },
      action_nat: {
        type: 'string',
        title: 'Action NAT64',
        enum: ['none', 'start', 'stop']
      },
      action_network: {
        type: 'string',
        title: 'Action Network',
        enum: ['none', 'start', 'stop']
      },
      action_diags: {
        type: 'string',
        title: 'Action Diagnostics',
        enum: ['none', 'start', 'stop']
      },
      action_serial: {
        type: 'string',
        title: 'Action KSH',
        enum: ['none', 'start', 'stop']
      },
      /*
            bagent_cm: {
              type: 'number',
              title: 'Border Agent: Connection Mode',
              readOnly: true
            },
            bagent_port: {
              type: 'number',
              title: 'Border Agent: MC port',
              readOnly: true
            },
            bagent_tis: {
              type: 'number',
              title: 'Border Agent: Thread Interface Status',
              readOnly: true
            },
            bridging_mark: {
              type: 'number',
              title: 'Bridging mark',
              readOnly: true
            },
            bridging_table: {
              type: 'string',
              title: 'Bridging table',
              readOnly: true
            },
            dhcp_pool: {
              type: 'string',
              title: 'DHCPv6 pool'
            },
            dhcp_server: {
              type: 'string',
              title: 'DHCPv6 server'
            },
            dongle_channel: {
              type: 'number',
              title: 'Channel',
              enum: [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]
            },
            dongle_mac: {
              type: 'string',
              title: 'MAC',
              readOnly: true
            },
            dongle_name: {
              type: 'string',
              title: 'Dongle name'
            },
            dongle_netname: {
              type: 'string',
              title: 'Network name',
              readOnly: true
            },
            dongle_panid: {
              type: 'string',
              title: 'PAN ID',
              maxLength: 4,
              readOnly: true
            },
            dongle_role: {
              type: 'string',
              title: 'Device role',
              readOnly: true
            },
            dongle_serial: {
              type: 'string',
              title: 'Serial number',
              readOnly: true
            },
            dongle_status: {
              type: 'string',
              title: 'Device status',
              readOnly: true
            },
            dongle_xpanid: {
              type: 'string',
              title: 'Extended PAN ID',
              readOnly: true
            },
            exterior_ifname: {
              type: 'string',
              title: 'Exterior interface name',
              readOnly: true
            },
            exterior_ipv4: {
              type: 'string',
              title: 'Exterior IPv4 address',
              readOnly: true
            },
            exterior_ipv6: {
              type: 'string',
              title: 'Exterior IPv6 address',
              readOnly: true
            },
            exterior_port_mc: {
              type: 'number',
              title: 'Exterior commissioning port',
              readOnly: true
            },
            interior_ifname: {
              type: 'string',
              title: 'Interior interface name',
              readOnly: true
            },
            interior_ifnumber: {
              type: 'number',
              title: 'Interior interface number',
              readOnly: true
            },
            dongle_rloc: {
              type: 'string',
              title: 'Interior IPv6 address',
              readOnly: true
            },
            interior_mac: {
              type: 'string',
              title: 'Interior MAC',
              readOnly: true
            },
            leader: {
              type: 'string',
              title: 'Leader',
              enum: ['yes', 'no']
            },
            pool4: {
              type: 'string',
              title: 'Pool 4',
              readOnly: true
            },
            prefix: {
              type: 'string',
              title: 'IPv6 prefix',
              readOnly: true
            },
            serial_device: {
              type: 'string',
              title: 'Serial device',
              readOnly: true
            },
      */
      status_dhcp: {
        type: 'string',
        title: 'Status DHCPv6',
        readOnly: true
      },
      status_mdns: {
        type: 'string',
        title: 'Status mDNS',
        readOnly: true
      },
      status_nat: {
        type: 'string',
        title: 'Status NAT64',
        readOnly: true
      },
      status_network: {
        type: 'string',
        title: 'Status Network',
        readOnly: true
      },
      status_diags: {
        type: 'string',
        title: 'Status Diagnostics',
        readOnly: true
      },
      status_serial: {
        type: 'string',
        title: 'Status KSH',
        readOnly: true
      }
    },
    "value": data,
    onSubmit: function (errors, values) {
      if (errors) {
        $('#res').html('<p>Errors.</p>');
      } else {
        $('#res').html('<p> Number of elements: ' + Object.keys(values).length + '</p>');
        $.ajax({
          type: 'POST',
          data: JSON.stringify(values),
          contentType: 'application/json',
          url: "http://" + window.location.hostname + ":11759/db/cfg",
          success: function () {
            // TODO: disable button here while waiting
            setTimeout(function () {
              window.location.reload(false);
            }, 3500);
          }
        });
      }
    }
  });
});
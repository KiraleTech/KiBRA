#!/usr/bin/python3
'''Kirale Border Router Administration'''

import argparse
import asyncio
import logging

import daemonize
import kibra
from kibra import database as db
from kibra import topology as topology
from kibra import webserver as webserver
from kibra.coapserver import COAPSERVER
from kibra.dhcp import DHCP
from kibra.diags import DIAGS
from kibra.dns import DNS
from kibra.ksh import SERIAL, enable_ncp
from kibra.ktask import status
from kibra.mdns import MDNS
from kibra.nat import NAT
from kibra.network import NETWORK, global_netconfig
from kibra.syslog import SYSLOG

PID_FILE = '/tmp/kibra.pid'

TASKS = []
SERVER = None


async def _master():
    # TODO: Have a way to completely stop the daemon
    while True:
        # Start over
        db.set('status_kibra', 'stopped')

        # Wait until the start command is received
        while db.get('action_kibra') != 'start':
            await asyncio.sleep(0.2)

        # Start all tasks
        db.set('status_kibra', 'starting')
        for thread in TASKS:
            if db.get('status_' + thread.name) is not status.RUNNING:
                asyncio.ensure_future(thread.run())

        # Wait until all tasks have started
        for thread in TASKS:
            while db.get('status_' + thread.name) is not status.RUNNING:
                await asyncio.sleep(1)
        db.set('action_kibra', 'none')
        db.set('status_kibra', 'running')
        db.save()
        logging.info('All tasks have now started.')

        # Run forever
        tasks_alive = True
        while tasks_alive:
            tasks_alive = False
            for thread in TASKS:
                if db.get('status_' + thread.name) is status.RUNNING:
                    tasks_alive = True
                    break
            await asyncio.sleep(0.2)

            # Kill all tasks if stop command is received
            if db.get('action_kibra') == 'stop':
                db.set('status_kibra', 'stopping')
                for thread in TASKS:
                    db.set('action_' + thread.name, 'kill')
                db.set('action_kibra', 'none')
                logging.info('Killing all tasks...')

        db.set('status_kibra', 'stopped')
        logging.info('All tasks have now stopped.')


def _main():
    global SERVER

    logging.info('Launching KiBRA v%s' % kibra.__version__)

    # Load database
    db.load()

    # Exterior network configuration
    global_netconfig()

    # Find connected dongle
    enable_ncp()

    # Start web interface
    webserver.start()

    # Start subtasks
    mdns = MDNS()
    TASKS.append(NETWORK())
    TASKS.append(SERIAL())
    TASKS.append(SYSLOG())
    TASKS.append(DHCP())
    TASKS.append(NAT())
    TASKS.append(DNS())
    TASKS.append(mdns)
    TASKS.append(DIAGS())
    TASKS.append(COAPSERVER())

    # Launch mDNS already
    asyncio.ensure_future(mdns.run())

    if db.get('autostart') == 1:
        db.set('action_kibra', 'start')

    asyncio.ensure_future(_master())

    asyncio.get_event_loop().run_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='kibra', description='Kirale Border Router Administration'
    )
    parser.add_argument(
        '--daemon', required=False, action='store_true', help='run as a daemon'
    )
    parser.add_argument(
        '--form', required=False, action='store_true', help='form topology'
    )
    parser.add_argument(
        '--clear', required=False, action='store_true', help='clear topology'
    )
    parser.add_argument(
        '--version', action='version', version='%s' % kibra.__version__
    )
    args = parser.parse_args()

    # Configure logging
    # TODO: log file folder might not exist
    logging.basicConfig(
        level=logging.INFO,
        format='\r%(asctime)s - %(levelname)s [%(module)s]: %(message)s',
        filename=db.LOG_FILE,
        filemode='w',
    )

    if args.form:
        topology.form_topology()
    elif args.clear:
        topology.clear_topology()
    elif args.daemon:
        daemonize.Daemonize(app='KiBRA', pid=PID_FILE, action=_main).start()
    else:
        _main()

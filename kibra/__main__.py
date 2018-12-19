#!/usr/bin/python3
'''Kirale Border Router Administration'''

import asyncio
import argparse
import asyncio
import logging
from time import sleep

from kibra import database as db
from kibra import topology as topology
from kibra import webserver as webserver
from kibra.coapserver import COAPSERVER

from kibra.dhcp import DHCP
from kibra.diags import DIAGS
from kibra.dns import DNS
from kibra.ktask import status
from kibra.mdns import MDNS
from kibra.nat import NAT
from kibra.network import NETWORK
from kibra.ksh import enable_ecm, SERIAL

TASKS = []
SERVER = None

async def _master():
    # TODO: Have a way to completely stop the daemon
    while True:
        # Wait until the start command is received
        db.set('status_kibra', 'stopped')
        while db.get('action_kibra') != 'start':
            await asyncio.sleep(0.2)

        # Start all tasks
        for thread in TASKS:
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
                for thread in TASKS:
                    db.set('action_' + thread.name, 'kill')
                db.set('action_kibra', 'none')
                logging.info('Killing all tasks...')
        
        db.set('status_kibra', 'stopped')
        logging.info('All tasks have now stopped.')

def _main():
    global SERVER

    # Load database
    db.load()

    # Find connected dongle
    enable_ecm()

    # Start web interface
    webserver.start()

    loop = asyncio.get_event_loop()

    # Start subtasks
    TASKS.append(SERIAL())
    TASKS.append(NETWORK())
    TASKS.append(DHCP())
    TASKS.append(NAT())
    TASKS.append(DNS())
    TASKS.append(MDNS())
    TASKS.append(DIAGS())
    TASKS.append(COAPSERVER())

    if db.get('autostart') == 1:
        db.set('action_kibra', 'start')
    
    asyncio.ensure_future(_master())
    
    loop.run_forever()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='kibra', description='Kirale Border Router Administration')
    parser.add_argument(
        '--form', required=False, action='store_true', help='form topology')
    parser.add_argument(
        '--clear', required=False, action='store_true', help='clear topology')
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='\r%(asctime)s - %(levelname)s [%(module)s]: %(message)s')

    if args.form:
        topology.form_topology()
    elif args.clear:
        topology.clear_topology()
    else:
        _main()

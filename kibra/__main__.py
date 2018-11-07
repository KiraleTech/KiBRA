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
from kibra.ksh import SERIAL

TASKS = []
SERVER = None

async def _master():
    # Wait until all tasks have started
    for thread in TASKS:
        while db.get('status_' + thread.name) is not status.RUNNING:
            await asyncio.sleep(1)
    logging.info('All tasks have now started.')
    db.save()

    # Run forever
    tasks_alive = True
    while tasks_alive:
        tasks_alive = False
        for thread in TASKS:
            if db.get('status_' + thread.name) is status.RUNNING:
                tasks_alive = True
        await asyncio.sleep(0.2)

    logging.info('Bye bye!')

def _main():
    global SERVER

    # Load database
    db.load()

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
    
    asyncio.ensure_future(_master())
    for thread in TASKS:
        asyncio.ensure_future(thread.run())
    
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

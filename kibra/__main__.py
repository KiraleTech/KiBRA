#!/usr/bin/python3
'''Kirale Border Router Administration'''

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

THREADS = []
SERVER = None


def _main():
    global SERVER

    # Load database
    db.load()

    # Start web interface
    webserver.start()

    # Start subtasks
    THREADS.append(SERIAL())
    THREADS.append(NETWORK())
    #THREADS.append(DHCP())
    #THREADS.append(NAT())
    #THREADS.append(DNS())
    THREADS.append(MDNS())
    THREADS.append(DIAGS())
    THREADS.append(COAPSERVER())
    for thread in THREADS:
        thread.start()

    # Wait until all tasks have started
    try:
        for thread in THREADS:
            while db.get('status_' + thread.name) is not status.RUNNING:
                sleep(1)
        logging.info('All tasks have now started.')
        db.save()
    except KeyboardInterrupt:
        logging.info('Attempting to close all tasks, please wait...')
        for thread in THREADS:
            thread.kill()

    # Do nothing until Control+C is pressed
    tasks_alive = True
    try:
        while tasks_alive:
            tasks_alive = False
            for thread in THREADS:
                if db.get('status_' + thread.name) is status.RUNNING:
                    tasks_alive = True
            sleep(0.2)
    except KeyboardInterrupt:
        logging.info('Attempting to close all tasks, please wait...')
        for thread in THREADS:
            thread.kill()

    # Let tasks finish
    for thread in THREADS:
        thread.join()
    logging.info('All tasks stopped.')
    logging.info('Bye bye!')


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

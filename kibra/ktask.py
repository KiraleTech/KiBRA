import abc
import logging
from threading import Thread
from time import sleep

import kibra.database as db


class status:
    STARTING = 'starting'
    RUNNING = 'running'
    STOPPED = 'stopped'
    STOPPING = 'stopping'
    ERRORED = 'errored'


class action:
    NONE = 'none'
    START = 'start'
    STOP = 'stop'
    KILL = 'kill'


class Ktask(Thread):
    __metaclass__ = abc.ABCMeta

    def __init__(self,
                 name,
                 start_keys=[],
                 stop_keys=[],
                 start_tasks=[],
                 stop_tasks=[],
                 period=2):
        super(Ktask, self).__init__()
        self.name = name
        self.status_key = 'status_' + name
        self.action_key = 'action_' + name
        self.start_keys = start_keys
        self.stop_keys = stop_keys
        self.start_tasks = start_tasks
        self.stop_tasks = stop_tasks
        self.period = period

    @abc.abstractmethod
    def kstart(self):
        '''Start.'''

    @abc.abstractmethod
    def kstop(self):
        '''Stop.'''

    def periodic(self):
        pass

    def check_status(self):
        return status.STOPPED

    def kill(self):
        logging.info('Killing task [%s]...', self.name)
        db.set(self.action_key, action.KILL)
        db.set(self.status_key, status.STOPPING)

    def run(self):
        logging.info('Loading task [%s]...', self.name)
        self.is_alive = True

        # Preconfiguration
        if self.check_status() is status.STOPPED:
            db.set(self.status_key, status.STOPPED)
            db.set(self.action_key, action.START)

        # Loop
        while self.is_alive:
            task_status = db.get(self.status_key)
            task_action = db.get(self.action_key)
            # Stopped case
            if task_status is status.STOPPED:
                # Start task if needed
                if task_action is action.START:
                    db.set(self.status_key, status.STARTING)
                    # Wait for tasks
                    for task in self.start_tasks:
                        logging.info('Task [%s] is waiting for [%s] to start.',
                                     self.name, task)
                        while db.get('status_' + task) is not status.RUNNING:
                            sleep(1)
                    # Wait for keys
                    while not db.has_keys(self.start_keys):
                        sleep(1)
                    try:
                        self.kstart()
                        db.set(self.status_key, status.RUNNING)
                        logging.info('Task [%s] has now started.', self.name)
                    except Exception as exc:
                        db.set(self.status_key, status.ERRORED)
                        logging.error('Task [%s] errored on start: %s',
                                      self.name, exc)
                    db.set(self.action_key, action.NONE)
                elif task_action is action.KILL:
                    self.is_alive = False
            # Running case
            if task_status is status.RUNNING:
                # Check if other dependant tasks have stopped or errored
                for task in self.start_tasks:
                    if db.get('status_' + task) is not status.RUNNING:
                        logging.info(
                            'Task [%s] stopped and forced [%s] to stop.', task,
                            self.name)
                        self.kill()
                        break
                # Periodic tasks
                if task_action is action.NONE:
                    # Avoid execution on start/stop processes
                    self.periodic()
            # Stop task if needed
            if task_status is status.STOPPING:
                if (task_action is action.STOP) or (task_action is
                                                    action.KILL):
                    if db.has_keys(self.stop_keys):
                        for task in self.stop_tasks:
                            logging.info(
                                'Task [%s] is waiting for [%s] to stop.',
                                self.name, task)
                            while db.get('status_' +
                                         task) is not status.STOPPED:
                                sleep(1)
                        self.kstop()
                        if task_action is action.KILL:
                            self.is_alive = False
                        db.set(self.action_key, action.NONE)
                        db.set(self.status_key, status.STOPPED)
                        logging.info('Task [%s] has now stopped.', self.name)
            # All cases
            sleep(self.period)

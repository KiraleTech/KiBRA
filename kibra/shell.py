import logging
from bash import bash as alexcouperbash
from colorama import Fore
from colorama import init as colinit

DEBUG = True

# TODO: https://docs.python.org/3/library/asyncio-subprocess.html

def bash(command):
    if DEBUG:
        '''
        colinit()
        print('%s%s%s> %s%s%s' % (Fore.YELLOW, 'bash', Fore.RESET, Fore.CYAN,
                                  command, Fore.RESET))
        '''
        logging.info('bash> %s', command)
    stdout = alexcouperbash(command)
    if stdout:
        '''
        if DEBUG:
            print('%s%s%s' % (Fore.MAGENTA, stdout, Fore.RESET))
        '''
        logging.info(stdout)
        return stdout

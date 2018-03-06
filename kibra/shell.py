from bash import bash as alexcouperbash

from colorama import init as colinit
from colorama import Fore

DEBUG = False


def bash(command):
    if DEBUG:
        colinit()
        print('%s%s%s> %s%s%s' % (Fore.YELLOW, 'bash', Fore.RESET, Fore.CYAN,
                                  command, Fore.RESET))
    stdout = alexcouperbash(command)
    if stdout:
        if DEBUG:
            print('%s%s%s' % (Fore.MAGENTA, stdout, Fore.RESET))
        return stdout

from bash import bash as alexcouperbash
from colorama import Fore
from colorama import init as colinit

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

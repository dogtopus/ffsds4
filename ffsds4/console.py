#!/usr/bin/env python3

import cmd
import contextlib
import logging
import functionfs.gadget
import threading
import os
import signal
from typing import Iterator, TYPE_CHECKING
from . import ds4

if TYPE_CHECKING:
    from . import DS4Function

logger = logging.getLogger('ffsds4.console')

class Console(cmd.Cmd):
    intro = ('FFSDS4 Console\n'
             'Type "help" for usage.')
    prompt = '(ffsds4) '
    def __init__(self, function: "DS4Function", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._function = function
        self._tracker = function.tracker

    def _wait_for_connect(self):
        if self._function.connected.wait(1):
            return True
        else:
            print('USB not connected.')
            return False

    def do_exit(self, _arg):
        logger.debug('Sending SIGINT to ourselves...')
        os.kill(os.getpid(), signal.SIGINT)
        return True

    def do_presstest(self, _arg):
        if self._wait_for_connect():
            with self._tracker.start_modify_report() as report:
                report: ds4.InputReport
                report.set_button(ds4.ButtonType.ps, True)

    def do_connected(self, _arg):
        print('Connected.' if self._function.connected.is_set() else 'Disconnected.')

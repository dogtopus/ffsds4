#!/usr/bin/env python3

import cmd
import logging
import functionfs.gadget
import threading
import os
import signal
from . import ds4

logger = logging.getLogger('ffsds4.console')

class Console(cmd.Cmd):
    intro = ('FFSDS4 Console\n'
             'Type "help" for usage.')
    prompt = '(ffsds4) '
    def __init__(self, tracker: ds4.DS4StateTracker, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tracker = tracker

    def do_exit(self, _arg):
        logger.debug('Sending SIGINT to ourselves...')
        os.kill(os.getpid(), signal.SIGINT)
        return True

    def do_presstest(self, _arg):
        with self._tracker.start_modify_report() as report:
            report: ds4.InputReport
            report.set_button(ds4.ButtonType.ps, True)

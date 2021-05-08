#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of FFSDS4
# Copyright (C) 2021-  dogtopus

import cmd
import contextlib
import logging
import functionfs.gadget
import threading
import os
import signal
from typing import Iterator, TYPE_CHECKING
from . import ds4, sequencer

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
        self._sequencer = sequencer.Sequencer(self._tracker)
        self._sequencer.start()

    def _wait_for_connect(self):
        if self._function.connected.wait(1):
            return True
        else:
            print('USB not connected.')
            return False

    def do_exit(self, _arg):
        self._sequencer.shutdown()
        logger.debug('Sending SIGINT to ourselves...')
        os.kill(os.getpid(), signal.SIGINT)
        return True

    def do_presstest(self, _arg):
        if self._wait_for_connect():
            self._sequencer.queue_press_buttons({ ds4.ButtonType.ps })

    def do_connected(self, _arg):
        print('Connected.' if self._function.connected.is_set() else 'Disconnected.')

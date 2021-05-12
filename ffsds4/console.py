#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of FFSDS4
# Copyright (C) 2021-  dogtopus

import argparse
import cmd
import contextlib
import functools
import logging
import functionfs.gadget
import threading
import os
import shlex
import signal
from typing import Iterator, TYPE_CHECKING, Optional, Callable
from . import ds4, sequencer

if TYPE_CHECKING:
    from . import DS4Function

logger = logging.getLogger('ffsds4.console')

ConsoleDoMethod = Callable[['Console', str], Optional[bool]]
ConsoleArgparseDoMethod = Callable[['Console', argparse.Namespace], Optional[bool]]

def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='')
    sps = p.add_subparsers(dest='cmd', help='Command.')

    sp = sps.add_parser('press')
    sp.add_argument('-t', '--hold-time', help='Time to hold the buttons.')
    sp.add_argument('buttons', nargs='+', help='Buttons to press.')
    return p

def wait_for_connect(func: ConsoleDoMethod) -> ConsoleDoMethod:
    @functools.wraps(func)
    def _wrapper(self: 'Console', args: str) -> Optional[bool]:
        if self._function.connected.wait(1):
            return func(self, args)
        else:
            print('USB not connected.')
            return None
    return _wrapper


def use_argparse(func: ConsoleArgparseDoMethod) -> ConsoleDoMethod:
    @functools.wraps(func)
    def _wrapper(self: 'Console', args: str) -> Optional[bool]:
        try:
            parsed_args = self._parser.parse_args()
            return func(self, parsed_args)
        except SystemExit:
            return None
    return _wrapper


class Console(cmd.Cmd):
    _function: "DS4Function"
    _tracker: ds4.DS4StateTracker
    _sequencer: sequencer.Sequencer
    _parser: argparse.ArgumentParser

    intro = ('FFSDS4 Console\n'
             'Type "help" for usage.')
    prompt = '(ffsds4) '
    def __init__(self, function: "DS4Function", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._function = function
        self._tracker = function.tracker
        self._sequencer = sequencer.Sequencer(self._tracker)
        self._sequencer.start()
        self._parser = create_parser()

    def do_exit(self, _arg):
        self._sequencer.shutdown()
        logger.debug('Sending SIGINT to ourselves...')
        os.kill(os.getpid(), signal.SIGINT)
        return True

    @wait_for_connect
    def do_presstest(self, _arg):
        self._sequencer.queue_press_buttons({ ds4.ButtonType.ps })

    def do_connected(self, _arg):
        print('Connected.' if self._function.connected.is_set() else 'Disconnected.')

    def do_EOF(self, _arg):
        return self.do_exit(_arg)

    def do_help(self, arg):
        args = shlex.split(arg)
        try:
            if len(args) == 0:
                self._parser.parse_args(('--help', ))
            else:
                self._parser.parse_args((args[0], '--help'))
        except SystemExit:
            return

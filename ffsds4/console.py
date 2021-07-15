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
from typing import Iterator, TYPE_CHECKING, Optional, Callable, Sequence, Set, Tuple
from . import ds4, sequencer

if TYPE_CHECKING:
    from . import DS4Function

logger = logging.getLogger('ffsds4.console')

ConsoleDoMethod = Callable[['Console', str], Optional[bool]]
ConsoleArgparseDoMethod = Callable[['Console', argparse.Namespace], Optional[bool]]

def create_parser() -> argparse.ArgumentParser:
    button_choices = tuple(item.name for item in ds4.ButtonType) + tuple(f'd:{item.name}' for item in ds4.DPadPosition)

    p = argparse.ArgumentParser(prog='')
    sps = p.add_subparsers(dest='cmd', help='Command.')

    sp = sps.add_parser('press', help='Press the specified buttons.')
    sp.add_argument('-t', '--hold-time', type=float, help='Time to hold the buttons.')
    sp.add_argument('buttons', metavar='button', nargs='+', choices=button_choices, help='Buttons to press.')

    sp = sps.add_parser('hold', help='Press and hold a button indefinitely.')
    sp.add_argument('buttons', metavar='button', nargs='+', choices=button_choices, help='Buttons to hold.')

    sp = sps.add_parser('release', help='Unconditionally release previously held buttons.')
    sp.add_argument('buttons', metavar='button', nargs='+', choices=button_choices, help='Buttons to hold.')
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


def use_argparse(insert_subcmd: Optional[str] = None) -> Callable[[ConsoleArgparseDoMethod], ConsoleDoMethod]:
    def _decorator(func: ConsoleArgparseDoMethod) -> ConsoleDoMethod:
        @functools.wraps(func)
        def _wrapper(self: 'Console', args: str) -> Optional[bool]:
            shlex_args = shlex.split(args)
            if insert_subcmd is not None:
                shlex_args.insert(0, insert_subcmd)
            try:
                parsed_args = self._parser.parse_args(shlex_args)
                return func(self, parsed_args)
            except SystemExit:
                return None
            except Exception:
                # Anti-crash
                return None
        return _wrapper
    return _decorator


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

    def do_help(self, arg: str):
        args = shlex.split(arg)
        try:
            if len(args) == 0:
                self._parser.parse_args(('--help', ))
            else:
                self._parser.parse_args((args[0], '--help'))
        except SystemExit:
            return

    def do_exit(self, _arg: str):
        self._sequencer.shutdown()
        logger.debug('Sending SIGINT to ourselves...')
        os.kill(os.getpid(), signal.SIGINT)
        return True

    def do_EOF(self, _arg: str):
        return self.do_exit(_arg)

    @staticmethod
    def _parse_button_type(button_names: Sequence[str]) -> Tuple[Set[ds4.ButtonType], Optional[ds4.DPadPosition]]:
        dpad_pos: Optional[ds4.DPadPosition]
        buttons: Set[ds4.ButtonType]

        dpad_pos = None
        buttons = set()

        for name in button_names:
            # DPad
            if name.startswith('d:'):
                if dpad_pos is not None:
                    raise RuntimeError(f'Duplicate DPad position {name}')
                dpad_pos = ds4.DPadPosition[name.split(':')[1]]
            else:
                buttons.add(ds4.ButtonType[name])
        return buttons, dpad_pos

    @wait_for_connect
    @use_argparse('press')
    def do_press(self, args: argparse.Namespace):
        hold_time: Optional[float]
        hold_time = args.hold_time

        buttons, dpad_pos = self._parse_button_type(args.buttons)

        if dpad_pos is not None:
            self._sequencer.queue_press_dpad(dpad_pos)
        if len(buttons) != 0:
            self._sequencer.queue_press_buttons(buttons, hold_time if hold_time is not None else 0.05)

    @wait_for_connect
    @use_argparse('hold')
    def do_hold(self, args: argparse.Namespace):
        buttons, dpad_pos = self._parse_button_type(args.buttons)

        if dpad_pos is not None:
            self._sequencer.queue_press_dpad(dpad_pos)
        if len(buttons) != 0:
            self._sequencer.hold_buttons(buttons)

    @wait_for_connect
    @use_argparse('release')
    def do_release(self, args: argparse.Namespace):
        buttons, dpad_pos = self._parse_button_type(args.buttons)

        if dpad_pos is not None:
            self._sequencer.queue_press_dpad(ds4.DPadPosition.neutral)
        if len(buttons) != 0:
            self._sequencer.release_buttons(buttons)

    def do_connected(self, _arg: str):
        print('Connected.' if self._function.connected.is_set() else 'Disconnected.')

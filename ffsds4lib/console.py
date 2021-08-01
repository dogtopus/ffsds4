#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of FFSDS4
# Copyright (C) 2021-  dogtopus
from __future__ import annotations

import argparse
import cmd
import contextlib
import functools
import logging
import math
import threading
import os
import shlex
import signal
from typing import Iterator, TYPE_CHECKING, Optional, Callable, Sequence, Set, Tuple

import functionfs.gadget
import sty

from . import ds4, sequencer

if TYPE_CHECKING:
    from . import DS4Function

logger = logging.getLogger('ffsds4.console')

ConsoleDoMethod = Callable[['Console', str], Optional[bool]]
ConsoleArgparseDoMethod = Callable[['Console', argparse.Namespace], Optional[bool]]

BARS = '▁▂▃▄▅▆▇█'

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

    sp = sps.add_parser('stick_set', help='Set stick position.')
    mxg = sp.add_mutually_exclusive_group()
    mxg.add_argument('-c', '--cartesian', action='store_const', dest='unit', const='cartesian', default='cartesian', help='Use cartesian coordinates. The values must be in the range of (-1, 1) (default).')
    mxg.add_argument('-p', '--polar', action='store_const', dest='unit', const='polar', help='Use polar coordinates The values must be in the range of ((-1, 1), (0, 360)).')
    mxg.add_argument('-r', '--raw', action='store_const', dest='unit', const='raw', help='Use raw coordinates. The values must be in the range of (0, 256).')
    sp.add_argument('lx', type=float, help='Left X.')
    sp.add_argument('ly', type=float, help='Left Y.')
    sp.add_argument('rx', type=float, help='Right X.')
    sp.add_argument('ry', type=float, help='Right Y.')

    sp = sps.add_parser('stick_release', help='Release all sticks.')

    sp = sps.add_parser('feedback', help='Read feedback report.')
    sp.add_argument('field', choices=('led', 'rumble'), help='Field to read.')

    return p

def wait_for_connect(func: ConsoleDoMethod) -> ConsoleDoMethod:
    @functools.wraps(func)
    def _wrapper(self: Console, args: str) -> Optional[bool]:
        if self._function.connected.wait(1):
            return func(self, args)
        else:
            print('USB not connected.')
            return None
    return _wrapper


def use_argparse(insert_subcmd: Optional[str] = None) -> Callable[[ConsoleArgparseDoMethod], ConsoleDoMethod]:
    def _decorator(func: ConsoleArgparseDoMethod) -> ConsoleDoMethod:
        @functools.wraps(func)
        def _wrapper(self: Console, args: str) -> Optional[bool]:
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
                logger.exception('An unexpected exception occurred when executing command.')
                return None
        return _wrapper
    return _decorator


class Console(cmd.Cmd):
    _function: DS4Function
    _tracker: ds4.DS4StateTracker
    _sequencer: sequencer.Sequencer
    _parser: argparse.ArgumentParser

    intro = ('FFSDS4 Console\n'
             'Type "help" for usage.')
    prompt = '(ffsds4) '
    def __init__(self, function: DS4Function, *args, **kwargs):
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

    @wait_for_connect
    @use_argparse('stick_set')
    def do_stick_set(self, args: argparse.Namespace):
        self._sequencer.hold_stick((args.lx, args.ly), (args.rx, args.ry), unit=args.unit)

    @wait_for_connect
    @use_argparse('stick_release')
    def do_stick_release(self, args: argparse.Namespace):
        self._sequencer.release_stick()

    @wait_for_connect
    @use_argparse('feedback')
    def do_feedback(self, args: argparse.Namespace):
        if args.field == 'led':
            # Gamma corrected value (with gamma=1/3)
            r, g, b = (min(int(math.pow(c/255, 1/3) * 255), 255) for c in self._tracker.feedback_report.led_color)
            flash_on, flash_off = self._tracker.feedback_report.led_flash_on, self._tracker.feedback_report.led_flash_off
            print(f'{sty.fg(r, g, b)}●{sty.fg.rs} #{r:02x}{g:02x}{b:02x} ({flash_on} on {flash_off} off)')
        elif args.field == 'rumble':
            rl = self._tracker.feedback_report.rumble_left
            rr = self._tracker.feedback_report.rumble_right
            rl_intensity = '| |' if rl == 0 else f'|{BARS[min((rl - 1) // 32, 7)]}|'
            rr_intensity = '| |' if rr == 0 else f'|{BARS[min((rr - 1) // 32, 7)]}|'
            print(f'{rl_intensity} {rl:03d}   {rr_intensity} {rr:03d}')

    def do_fb(self, arg: str):
        return self.do_feedback(arg)

    def do_connected(self, _arg: str):
        print(f'{sty.fg.green}●{sty.fg.rs} Connected.' if self._function.connected.is_set() else f'{sty.fg.red}●{sty.fg.rs} Disconnected.')

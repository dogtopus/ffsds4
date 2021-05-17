#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of FFSDS4
# Copyright (C) 2021-  dogtopus

import enum
import functools
import threading
import queue
import time
import logging
from typing import Sequence, Optional, Set, Tuple, Any, Type, Union, Dict, MutableSequence, Callable, Mapping

from .ds4 import DS4StateTracker, ButtonType, InputReport, InputTargetType

logger = logging.getLogger('ffsds4.sequencer')


InputTypeIdentifier = Tuple[InputTargetType, Any]


class ControllerEventType(enum.Enum):
    press = enum.auto()
    release = enum.auto()

@functools.total_ordering
class ControllerEvent:
    target: InputTypeIdentifier
    next_: Optional["ControllerEvent"]
    def __init__(self, at: float, op: ControllerEventType, target: InputTypeIdentifier) -> None:
        self.at = at
        self.op = op
        self.target = target
        self.cancelled = False
        self.next_ = None

    def __lt__(self, other: object):
        if not isinstance(other, ControllerEvent):
            raise TypeError('Comparing ControllerEvent with non-ControllerEvent object is not supported.')
        return self.at < other.at

    def __eq__(self, other: object):
        if not isinstance(other, ControllerEvent):
            raise TypeError('Comparing ControllerEvent with non-ControllerEvent object is not supported.')
        return self.at == other.at

    def cancel(self) -> None:
        next_: Optional["ControllerEvent"] = self
        while next_ is not None:
            next_.cancelled = True
            next_ = next_.next_

    def chain(self, at: float, op: ControllerEventType, target: Tuple[InputTargetType, Any]) -> "ControllerEvent":
        self.next_ = ControllerEvent(at, op, target)
        return self.next_


class ReschedulableAlarm(threading.Thread):
    def __init__(self, func: Callable[..., None], args: Optional[Sequence[Any]]=None, kwargs: Optional[Mapping[Any, Any]]=None):
        self._func: Callable[..., None] = func
        self._args = args
        self._kwargs = kwargs
        self._at: Optional[float] = None
        self._timeout_or_cancel = threading.Condition()
        self._exit = threading.Event()

    def run(self):
        '''
        Alarm thread.
        '''
        while not self._exit.wait(0):
            with self._timeout_or_cancel:
                timeout = min(self._at - time.monotonic(), 0) if self._at is not None else None
                if not self._timeout_or_cancel.wait(timeout):
                    self._func(self._args, self._kwargs)
                if self._exit.wait(0):
                    break

    def reschedule(self, at: Optional[float] = None):
        '''
        Cancel the current running alarm and reschedule the alarm for another
        time.
        '''
        with self._timeout_or_cancel:
            self._at = at
            self._timeout_or_cancel.notify_all()

    def cancel(self):
        '''
        Cancel the current running alarm and put the thread to sleep
        indefinitely.
        '''
        self.reschedule()

    def stop(self):
        '''
        Cancel the current running alarm and signal the thread to shutdown.
        '''
        self._exit.set()
        self.cancel()


class Sequencer:
    _event_queue: queue.PriorityQueue[ControllerEvent]
    _holding: Dict[InputTypeIdentifier, ControllerEvent]
    def __init__(self, tracker: DS4StateTracker) -> None:
        self._tracker = tracker
        self._event_queue = queue.PriorityQueue()
        self._holding = {}
        self._tick_interval = 0.004
        self._min_release_time = self._tick_interval * 2
        self._tick_thread = threading.Thread(target=self._tick)
        self._shutdown_flag = threading.Event()
        self._mutex = threading.RLock()

    def _tick(self) -> None:
        logger.debug('Sequencer tick thread started.')
        try:
            while not self._shutdown_flag.wait(self._tick_interval):
                events: MutableSequence[ControllerEvent] = []
                # TODO should we just write our own synchronized PQ?
                with self._mutex:
                    with self._event_queue.mutex:
                        while self._event_queue._qsize() != 0:
                            current_time = time.monotonic()
                            # peek
                            if current_time >= self._event_queue.queue[0].at:
                                event = self._event_queue._get()
                                if not event.cancelled:
                                    events.append(event)
                            else:
                                break
                    if len(events) == 0:
                        continue
                    logger.debug('%d events collected', len(events))
                    with self._tracker.start_modify_report() as report:
                        for ev in events:
                            ev_on_type, ev_on_id = ev.target
                            if ev_on_type == ButtonType:
                                report.set_button(ev_on_id, ev.op == ControllerEventType.press)
                            if ev.next_ is None:
                                del self._holding[ev.target]

        except Exception:
            logger.exception('Unhandled exception in tick thread.')
            self._shutdown_flag.set()
            raise
        finally:
            logger.debug('Sequencer tick thread stopped.')

    def start(self) -> None:
        '''
        Start sequencer thread.
        '''
        self._shutdown_flag.clear()
        try:
            self._tick_thread.start()
        except RuntimeError:
            logger.debug('Attempting to restart the sequencer tick thread.')
            self._tick_thread = threading.Thread(target=self._tick)
            self._tick_thread.start()

    def shutdown(self) -> None:
        '''
        Shut down sequencer thread.
        '''
        logger.debug('Shutting down...')
        self._shutdown_flag.set()
        self._tick_thread.join()

    def queue_press_buttons(self, buttons: Set[ButtonType], hold: float = 0.05) -> None:
        '''
        Queue a timed button press event affecting one or more buttons.
        Previous queued events on affected buttons will be cancelled and a
        release event will be queued before the actual press and release
        event.
        '''
        start_time = time.monotonic()
        hold_until = start_time + hold
        with self._mutex:
            for button in buttons:
                target = (ButtonType, button)
                if target in self._holding:
                    # Cancel the ongoing event chain for this particular button
                    self._holding[target].cancel()
                    del self._holding[target]

                    # Force the button into release state
                    with self._tracker.start_modify_report() as report:
                        report.set_button(button, False)

                    # New event chain
                    event_press = ControllerEvent(at=start_time+self._min_release_time, op=ControllerEventType.press, target=target)
                    event_release_final = event_press.chain(at=hold_until+self._min_release_time, op=ControllerEventType.release, target=target)

                    self._holding[target] = event_press

                    # Ensure the button is released for at least _min_release_time seconds, then press it.
                    self._event_queue.put(event_press)
                    # At hold_until+_min_release_time time, release again
                    self._event_queue.put(event_release_final)
                else:
                    # Press the button
                    with self._tracker.start_modify_report() as report:
                        report.set_button(button, True)

                    # Hold until hold_until seconds later and release
                    event = ControllerEvent(at=hold_until, op=ControllerEventType.release, target=target)
                    self._holding[target] = event
                    self._event_queue.put(event)

    def hold_release_buttons(self, buttons: Set[ButtonType], release=False) -> None:
        '''
        Hold buttons indefinitely. Note that this will not generate a release
        event for holding initiated by queue_press_buttons but will cancel
        the event chain already in progress.

        If release is True, it will release the buttons unconditionally and
        cancel all related events.
        '''
        with self._tracker.start_modify_report() as report, self._mutex:
            for button in buttons:
                target = (ButtonType, button)
                if target in self._holding:
                    # Cancel the ongoing event chain for this particular button
                    self._holding[target].cancel()
                    del self._holding[target]
                report.set_button(button, not release)

    def hold_buttons(self, buttons: Set[ButtonType]) -> None:
        '''
        Hold buttons indefinitely.

        Equivalent to Sequencer.hold_release_buttons(buttons, False)
        '''
        self.hold_release_buttons(buttons)

    def release_buttons(self, buttons: Set[ButtonType]) -> None:
        '''
        Unconditionally release buttons and cancel all pending events
        associated with them.

        Equivalent to Sequencer.hold_release_buttons(buttons, True)
        '''
        self.hold_release_buttons(buttons, True)

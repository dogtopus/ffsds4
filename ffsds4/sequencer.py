#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of FFSDS4
# Copyright (C) 2021-  dogtopus

import enum
import threading
import queue
import time
import logging
from typing import Sequence, Optional, Set, Tuple, Any, Type, Union, Dict

from .ds4 import DS4StateTracker, ButtonType, InputReport, InputTargetType

logger = logging.getLogger('ffsds4.sequencer')


InputTypeIdentifier = Union[
    Tuple[Type[ButtonType], Union[ButtonType, int]],
    # TODO add the rest
]


class ControllerEventType(enum.Enum):
    press = enum.auto()
    release = enum.auto()

class ControllerEvent:
    next_: Optional["ControllerEvent"]
    def __init__(self, op: ControllerEventType, target: Tuple[InputTargetType, Any]):
        self.op = op
        self.target = target
        self.cancelled = False
        self.next_ = None

    def cancel(self):
        next_ = self
        while next_ is not None:
            next_.cancelled = True
            next_ = next_.next_

    def chain(self, op: ControllerEventType, target: Tuple[InputTargetType, Any]) -> "ControllerEvent":
        self.next_ = ControllerEvent(op, target)
        return self.next_

class Sequencer:
    _event_queue: queue.PriorityQueue[Tuple[float, ControllerEvent]]
    _holding: Dict[InputTypeIdentifier, ControllerEvent]
    def __init__(self, tracker: DS4StateTracker):
        self._tracker = tracker
        self._event_queue = queue.PriorityQueue()
        self._holding = {}
        self._tick_interval = 0.004
        self._min_release_time = self._tick_interval * 2
        self._tick_thread = threading.Thread(target=self._tick)
        self._shutdown_flag = threading.Event()
        self._mutex = threading.RLock()

    def _tick(self):
        logger.debug('Sequencer tick thread started.')
        try:
            while not self._shutdown_flag.wait(self._tick_interval):
                events: Sequence[ControllerEvent] = []
                # TODO should we just write our own synchronized PQ?
                with self._mutex:
                    with self._event_queue.mutex:
                        while self._event_queue._qsize() != 0:
                            current_time = time.perf_counter()
                            # peek
                            if current_time >= self._event_queue.queue[0][0]:
                                _at, event = self._event_queue._get()
                                if not event.cancelled:
                                    events.append(event)
                            else:
                                break
                    if len(events) == 0:
                        continue
                    logger.debug('%d events collected', len(events))
                    with self._tracker.start_modify_report() as report:
                        report: InputReport
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

    def start(self):
        self._shutdown_flag.clear()
        try:
            self._tick_thread.start()
        except RuntimeError:
            logger.debug('Attempting to restart the sequencer tick thread.')
            self._tick_thread = threading.Thread(target=self._tick)
            self._tick_thread.start()

    def shutdown(self):
        logger.debug('Shutting down...')
        self._shutdown_flag.set()
        self._tick_thread.join()

    def queue_press_buttons(self, buttons: Set[ButtonType], hold: float = 0.05):
        start_time = time.perf_counter()
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
                    event_press = ControllerEvent(op=ControllerEventType.press, target=target)
                    event_release_final = event_press.chain(op=ControllerEventType.release, target=target)

                    self._holding[target] = event_press

                    # Ensure the button is released for at least _min_release_time seconds, then press it.
                    self._event_queue.put((start_time+self._min_release_time, event_press))
                    # At hold_until+_min_release_time time, release again
                    self._event_queue.put((hold_until+self._min_release_time, event_release_final))
                else:
                    # Press the button
                    with self._tracker.start_modify_report() as report:
                        report.set_button(button, True)

                    # Hold until hold_until seconds later and release
                    event = ControllerEvent(op=ControllerEventType.release, target=target)
                    self._holding[target] = event
                    self._event_queue.put((hold_until, event))

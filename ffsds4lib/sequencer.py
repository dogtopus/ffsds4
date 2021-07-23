#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of FFSDS4
# Copyright (C) 2021-  dogtopus

import cmath
import enum
import functools
import math
import threading
import queue
import time
import logging
import heapq
from typing import (
    Any,
    Sequence,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
    Dict,
    MutableSequence,
    Callable,
    Mapping,
    Generic,
    TypeVar,
    List,
    Iterable,
    Sized,
    Literal
)

from .ds4 import DS4StateTracker, ButtonType, InputReport, InputTargetType, DPadPosition

logger = logging.getLogger('ffsds4.sequencer')


InputTypeIdentifier = Tuple[InputTargetType, Any]


HOLDING_DPAD = (DPadPosition, None)
HOLDING_LSTICK = ('stick', 'l')
HOLDING_RSTICK = ('stick', 'r')


class ControllerEventType(enum.Enum):
    press = enum.auto()
    release = enum.auto()

@functools.total_ordering
class ControllerEvent:
    target: InputTypeIdentifier
    next_: Optional["ControllerEvent"]
    def __init__(self, at: float, op: ControllerEventType, target: InputTypeIdentifier, is_tween: Optional[bool] = False) -> None:
        self.at = at
        self.op = op
        self.target = target
        self.cancelled = False
        self.next_ = None
        self.is_tween = is_tween

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


HeapqElement = TypeVar('HeapqElement')
class HeapqWrapper(Generic[HeapqElement], Sized):
    def __init__(self, initial: Optional[Iterable[HeapqElement]] = None) -> None:
        self._list: List[HeapqElement] = list(initial) if initial is not None else []
        if len(self._list) != 0:
            heapq.heapify(self._list) 

    def __len__(self):
        return len(self._list)

    def push(self, val: HeapqElement) -> None:
        '''
        Push a value to the heap.
        '''
        heapq.heappush(self._list, val)

    def pop(self) -> HeapqElement:
        '''
        Pop the smallest value from the heap.
        '''
        return heapq.heappop(self._list)

    def peek(self) -> HeapqElement:
        '''
        Return the smallest value from the heap but do not remove it.
        '''
        return self._list[0]


class ReschedulableAlarm(threading.Thread):
    def __init__(self, func: Callable[..., None], args: Optional[Sequence[Any]]=None, kwargs: Optional[Mapping[Any, Any]]=None):
        super().__init__()
        self._func: Callable[..., None] = func
        self._args = args if args is not None else tuple()
        self._kwargs = kwargs if kwargs is not None else dict()
        self._at: Optional[float] = None
        self._timeout_or_cancel = threading.Condition()
        self._exit = False

    def run(self):
        '''
        Alarm thread.
        '''
        try:
            logger.debug('Sequencer alarm thread started.')
            with self._timeout_or_cancel:
                while not self._exit:
                    timeout = max(self._at - time.monotonic(), 0) if self._at is not None else None
                    if not self._timeout_or_cancel.wait(timeout):
                        self._func(*self._args, **self._kwargs)
                        self._at = None
        finally:
            logger.debug('Sequencer alarm thread stopped.')

    def reschedule(self, at: Optional[float] = None):
        '''
        Cancel the current running alarm and reschedule the alarm for another
        time.
        '''
        logger.debug('Rescheduling at %s', str(at))
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
        self._exit = True
        self.cancel()


class BaseTween:
    '''
    Base of tween objects.
    '''
    def __init__(self, start: float, duration: float, from_to: Tuple[float, float]) -> None:
        self.start = start
        self.duration = duration
        self.from_to = from_to
        self.done = False

    def at(self, t: float) -> float:
        '''
        Calculate the position based on the current timestamp.
        '''
        p = self.progression(t)
        if p >= 1:
            self.done = True
            return self.from_to[1]
        elif p < 0:
            return self.from_to[0]
        else:
            return self.from_to[0] + (self.from_to[1] - self.from_to[0]) * self._at(p)

    def _at(self, p: float) -> float:
        '''
        Actual implementation of the at algorithm. Takes a time progression
        variable p (0-1) and return the position (0-1).
        '''
        raise NotImplementedError('_at')

    def progression(self, t: float) -> float:
        return (t - self.start) / self.duration


class LinearTween(BaseTween):
    '''
    A linear tween.
    '''
    def _at(self, p: float) -> float:
        return p


class PolyEaseTween(BaseTween):
    """
    A polynomial ease inout tween. Based on https://easings.net/#easeInOutQuad.
    """
    def __init__(self, start: float, duration: float, from_to: Tuple[float, float], exp: float = 2):
        super().__init__(start, duration, from_to)
        self.exp = exp

    def _at(self, p: float) -> float:
        return (2 ** (self.exp - 1) * p ** self.exp) if p < 0.5 else (1 - (-2 * p + 2) ** self.exp / 2)


class Sequencer:
    _event_queue_new: HeapqWrapper[ControllerEvent]
    _holding: Dict[InputTypeIdentifier, ControllerEvent]
    def __init__(self, tracker: DS4StateTracker) -> None:
        self._tracker = tracker
        self._event_queue_new = HeapqWrapper()
        self._holding = {}
        self._tick_interval = 0.004
        self._min_release_time = max(1 / 60, self._tick_interval * 4)
        self._tick_thread = threading.Thread(target=self._tick)
        self._shutdown_flag = False
        self._mutex = threading.RLock()
        self._wakeup_cond = threading.Condition(self._mutex)
        self._alarm = ReschedulableAlarm(self._on_alarm)

    def _on_alarm(self) -> None:
        with self._mutex:
            self._wakeup_cond.notify_all()

    def _tick(self) -> None:
        logger.debug('Sequencer tick thread started.')
        try:
            while not self._shutdown_flag:
                events: MutableSequence[ControllerEvent] = []
                with self._mutex:
                    # Suspend until received wake up request.
                    self._wakeup_cond.wait()
                    while len(self._event_queue_new) != 0:
                        current_time = time.monotonic()
                        # peek
                        next_time = self._event_queue_new.peek().at
                        if current_time >= next_time:
                            event = self._event_queue_new.pop()
                            if not event.cancelled:
                                events.append(event)
                        else:
                            self._alarm.reschedule(next_time)
                            break
                    # TODO tween processing
                    if len(events) == 0:
                        continue
                    logger.debug('%d events collected', len(events))
                    with self._tracker.start_modify_report() as report:
                        for ev in events:
                            ev_on_type, ev_on_id = ev.target
                            if ev_on_type == ButtonType:
                                report.set_button(ev_on_id, ev.op == ControllerEventType.press)
                            elif ev_on_type == DPadPosition:
                                report.set_dpad(DPadPosition.neutral if ev.op == ControllerEventType.release else ev_on_id)
                            if ev.next_ is None:
                                del self._holding[ev.target if ev_on_type != DPadPosition else HOLDING_DPAD]

        except Exception:
            logger.exception('Unhandled exception in tick thread.')
            self._shutdown_flag = True
            raise
        finally:
            logger.debug('Sequencer tick thread stopped.')

    def _reschedule_alarm(self):
        self._alarm.reschedule(self._event_queue_new.peek().at)

    @staticmethod
    def _stick_to_native(xy: Tuple[float, float], unit: Literal['cartesian', 'polar', 'raw']) -> Tuple[int, int]:
        if unit == 'raw':
            return int(xy[0]), int(xy[1])
        elif unit == 'polar':
            # Abuse cmath.rect() to convert polar to cartesian coordinates
            rect = cmath.rect(xy[0], xy[1] / (180/math.pi))
            return max(min(round((rect.real+1) / 2 * 255), 255), 0), max(min(round((rect.imag+1) / 2 * 255), 255), 0)
        elif unit == 'cartesian':
            return max(min(round((xy[0]+1) / 2 * 255), 255), 0), max(min(round((xy[1]+1) / 2 * 255), 255), 0)
        else:
            raise ValueError('Invalid unit.')

    def start(self) -> None:
        '''
        Start sequencer thread.
        '''
        with self._mutex:
            self._shutdown_flag = False
        try:
            self._tick_thread.start()
        except RuntimeError:
            logger.debug('Attempting to restart the sequencer tick thread.')
            self._tick_thread = threading.Thread(target=self._tick)
            self._tick_thread.start()

        try:
            self._alarm.start()
        except RuntimeError:
            logger.debug('Attempting to restart the sequencer alarm thread.')
            self._alarm = ReschedulableAlarm(self._on_alarm)
            self._alarm.start()

    def shutdown(self) -> None:
        '''
        Shut down sequencer thread.
        '''
        logger.debug('Shutting down...')
        with self._mutex:
            self._shutdown_flag = True
            self._wakeup_cond.notify_all()
            self._alarm.stop()
        self._tick_thread.join()
        self._alarm.join()

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
                    self._event_queue_new.push(event_press)
                    # At hold_until+_min_release_time time, release again
                    self._event_queue_new.push(event_release_final)
                else:
                    # Press the button
                    with self._tracker.start_modify_report() as report:
                        report.set_button(button, True)

                    # Hold until hold_until seconds later and release
                    event = ControllerEvent(at=hold_until, op=ControllerEventType.release, target=target)
                    self._holding[target] = event
                    self._event_queue_new.push(event)
            self._reschedule_alarm()

    def queue_press_dpad(self, dpad_pos: DPadPosition, hold: float = 0.05) -> None:
        '''
        Queue a timed DPad press.
        Previous queued events on DPad will be cancelled and a release event
        will be queued before the actual press and release event.
        If dpad_pos is neutral, the DPad will be released and any unfinished
        events related to DPad will be cancelled.
        '''
        start_time = time.monotonic()
        hold_until = start_time + hold
        target = (DPadPosition, dpad_pos)

        if dpad_pos == DPadPosition.neutral:
            self.release_dpad()
            return

        with self._mutex:
            if HOLDING_DPAD in self._holding:
                # Cancel the ongoing event chain for DPad
                self._holding[HOLDING_DPAD].cancel()
                del self._holding[HOLDING_DPAD]

                # Force the DPad to go back to center
                with self._tracker.start_modify_report() as report:
                    report.set_dpad(DPadPosition.neutral)

                event_press = ControllerEvent(at=start_time+self._min_release_time, op=ControllerEventType.press, target=target)
                event_release_final = event_press.chain(at=hold_until+self._min_release_time, op=ControllerEventType.release, target=target)

                self._holding[HOLDING_DPAD] = event_press

                # Ensure the button is released for at least _min_release_time seconds, then press it.
                self._event_queue_new.push(event_press)
                # At hold_until+_min_release_time time, release again
                self._event_queue_new.push(event_release_final)
            else:
                # Press the DPad
                with self._tracker.start_modify_report() as report:
                    report.set_dpad(dpad_pos)

                # Hold until hold_until seconds later and release
                event = ControllerEvent(at=hold_until, op=ControllerEventType.release, target=target)
                self._holding[HOLDING_DPAD] = event
                self._event_queue_new.push(event)

            self._reschedule_alarm()

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

    def hold_release_dpad(self, dpad_pos: DPadPosition) -> None:
        '''
        Hold the DPad indefinitely. Note that this will not generate a release
        event for holding initiated by queue_press_dpad but will cancel
        the event chain already in progress.

        If release is True, it will release the DPad unconditionally and
        cancel all related events.
        '''
        with self._tracker.start_modify_report() as report, self._mutex:
            if HOLDING_DPAD in self._holding:
                # Cancel the ongoing event chain for this particular button
                self._holding[HOLDING_DPAD].cancel()
                del self._holding[HOLDING_DPAD]
            report.set_dpad(dpad_pos)

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

    def hold_dpad(self, dpad_pos: DPadPosition):
        self.hold_release_dpad(dpad_pos)

    def release_dpad(self):
        self.hold_release_dpad(DPadPosition.neutral)

    def _cancel_sticks(self):
        if HOLDING_LSTICK in self._holding:
            self._holding[HOLDING_LSTICK].cancel()
            del self._holding[HOLDING_LSTICK]
        if HOLDING_RSTICK in self._holding:
            self._holding[HOLDING_RSTICK].cancel()
            del self._holding[HOLDING_RSTICK]

    def hold_stick(self, left: Tuple[float, float], right: Tuple[float, float], unit: Literal['cartesian', 'polar', 'raw'] = 'cartesian') -> None:
        with self._tracker.start_modify_report() as report, self._mutex:
            self._cancel_sticks()
            report.set_stick(self._stick_to_native(left, unit), self._stick_to_native(right, unit))

    def release_stick(self):
        with self._tracker.start_modify_report() as report, self._mutex:
            self._cancel_sticks()
            report.set_stick((0x80, 0x80), (0x80, 0x80))
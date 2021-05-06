import threading
import queue
import time
import logging
from typing import Sequence, Optional, Set

from .ds4 import DS4StateTracker, ButtonType, InputReport

logger = logging.getLogger('ffsds4.sequencer')

class Sequencer:
    def __init__(self, tracker: DS4StateTracker):
        self._tracker = tracker
        self._event_queue = queue.PriorityQueue()
        self._holding = {}
        self._tick_interval = 0.004
        self._min_release_time = self._tick_interval * 2
        self._tick_thread = threading.Thread(target=self._tick)
        self._shutdown_flag = threading.Event()

    def _tick(self):
        logger.debug('Sequencer tick thread started.')
        try:
            while not self._shutdown_flag.wait(self._tick_interval):
                events = []
                # TODO should we just write our own synchronized PQ?
                with self._event_queue.mutex:
                    while self._event_queue._qsize() != 0:
                        current_time = time.perf_counter()
                        # peek
                        if current_time >= self._event_queue.queue[0][0]:
                            _, event = self._event_queue._get()
                            events.append(event)
                        else:
                            break
                if len(events) == 0:
                    continue
                logger.debug('%d events collected', len(events))
                with self._tracker.start_modify_report() as report:
                    report: InputReport
                    for ev in events:
                        ev_on_type, ev_on_id = ev['on']
                        if ev_on_type == ButtonType:
                            report.set_button(ev_on_id, False)
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
        with self._tracker.start_modify_report() as report:
            report: InputReport
            for button in buttons:
                report.set_button(button, True)
                # TODO handling cancellations
                event = {'type': 'release', 'on': (ButtonType, button), 'cancelled': False}
                self._holding[(ButtonType, button)] = event
                self._event_queue.put((hold_until, event))
                logger.debug('Event %s scheduled at %f', str(event), hold_until)

#!/usr/bin/env python
# This file is part of python-functionfs
# Copyright (C) 2018-2020  Vincent Pelletier <plr.vincent@gmail.com>
#
# python-functionfs is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-functionfs is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with python-functionfs.  If not, see <http://www.gnu.org/licenses/>.

"""
Third party PS4 controller emulator based on python-functionfs and its HID example.
"""
from __future__ import print_function
import ctypes
import functools
import errno
import functionfs
import importlib.resources
import logging
import threading
import sys
from . import descriptors, console
from functionfs.gadget import (
    GadgetSubprocessManager,
    ConfigFunctionFFSSubprocess,
)

from . import ds4

logger = logging.getLogger('ffsds4.manager')

REPORT_DESCRIPTOR = importlib.resources.read_binary(descriptors, 'ds43p.desc.bin')


class HIDINEndpoint(functionfs.EndpointINFile):
    """
    Customise what happens on IN transfer completion.
    In a real device, here may be where you would sample and clear the current
    movement deltas, and construct a new HID report to send to the host.
    """
    def __init__(self, controller_instance: "Controller", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._controller_instance = controller_instance

    def onComplete(self, buffer_list, user_data, status):
        if status < 0:
            if status == -errno.ESHUTDOWN:
                # Controller is unplugged, host selected another configuration, ...
                # Stop submitting the transfer.
                return False
            logger.error(f'IN endpoint failed {status}.')
            raise IOError(-status)
        # Buffer swapping
        with self._controller_instance.tracker.input_report_lock:
            self._controller_instance.tracker.swap_buffer_nolock()
            self._controller_instance.tracker.sync_buffer_nolock()
            return (self._controller_instance.tracker.input_report_buf.copy(), )


class HIDOUTEndpoint(functionfs.EndpointOUTFile):
    def __init__(self, controller_instance: "Controller", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._controller_instance = controller_instance

    def onComplete(self, data, status):
        if data is None:
            if status == -errno.ESHUTDOWN:
                return False
            logger.error(f'OUT endpoint failed {status}.')
            raise IOError(-status)
        self._controller_instance.tracker.process_feedback(data)
        return True


class DS4Function(functionfs.HIDFunction):
    """
    A simple mouse device.
    """
    def __init__(self, ds4key_path, **kw):
        super().__init__(
            report_descriptor=REPORT_DESCRIPTOR,
            in_report_max_length=64,
            out_report_max_length=64,
            **kw
        )
        global logger
        logger = logging.getLogger('ffsds4')
        logger.debug('Subprocess takeover.')
        # Load DS4Key
        with open(ds4key_path, 'rb') as f:
            ds4key = ds4.DS4Key(f)

        self.features = ds4.FeatureConfiguration(
            enable_touchpad=True,
            enable_rumble=True,
            enable_led=True,
            enable_imu=True
        )

        self.tracker = ds4.DS4StateTracker(ds4key, self.features)
        self.console = console.Console(self)
        self.connected = threading.Event()
        self.connected.clear()
        self.console_task = threading.Thread(target=self.console.cmdloop)
        logger.info('Gadget initialized. Dropping console.')
        self.console_task.start()

    def getEndpointClass(self, is_in, descriptor):
        """
        Tell HIDFunction that we want it to use our custom IN endpoint class
        for our only IN endpoint.
        """
        if is_in:
            return functools.partial(HIDINEndpoint, self)
        else:
            return functools.partial(HIDOUTEndpoint, self)

    def getHIDReport(self, value, index, length):
        """
        In case the host does not read our IN endpoint but instead uses the
        control endpoint to request reports.
        """
        report_type, report_id = ((value >> 8) & 0xff), (value & 0xff)
        if report_type == 0x03:
            if report_id == ds4.ReportType.get_auth_page_size:
                self.tracker.get_page_size(self.ep0)
            elif report_id == ds4.ReportType.get_auth_status:
                self.tracker.get_auth_status(self.ep0)
            elif report_id == ds4.ReportType.get_response:
                self.tracker.get_response(self.ep0)
            elif report_id == ds4.ReportType.get_feature_configuration:
                self.tracker.get_feature_configuration(self.ep0)

    def setHIDReport(self, value, index, length):
        report_type, report_id = ((value >> 8) & 0xff), (value & 0xff)
        if report_type == 0x03:
            if report_id == ds4.ReportType.set_challenge:
                self.tracker.set_challenge(self.ep0)

    def onEnable(self):
        """
        We are plugged to a host, it has enumerated and enabled us, start
        sending reports.
        """
        super().onEnable()
        self.getEndpoint(1).submit(
            (self.tracker.input_report_buf.copy(), ),
        )
        self.connected.set()
        logger.info('USB device connected.')

    def onDisable(self):
        super().onDisable()
        self.connected.clear()
        logger.info('USB device disconnected.')


def create_gadget_instance(args):
    try:
        return GadgetSubprocessManager(
            args=args,
            config_list=[
                # A single configuration
                {
                    'function_list': [
                        functools.partial(
                            ConfigFunctionFFSSubprocess,
                            getFunction=functools.partial(DS4Function, args.ds4key)
                        ),
                    ],
                    'MaxPower': 500,
                    'lang_dict': {
                        0x409: {
                            'configuration': 'Third-party PS4 controller function',
                        },
                    },
                }
            ],
            idVendor=0x1d6b, # Linux Foundation
            idProduct=0x0104, # Multifunction Composite Gadget
            lang_dict={
                0x409: {
                    'product': 'FFSDS4 composite device',
                    'manufacturer': 'python-functionfs',
                },
            },
        )
    except FileNotFoundError:
        logger.error('Some of the configfs/sysfs entries used by FunctionFS are missing. Did you forget to load the drivers?')
        raise

def parse_loglevel(level):
    try:
        level = int(level)
    except ValueError:
        pass
    return level

def parse_args():
    p = GadgetSubprocessManager.getArgumentParser(
        description='DS4 emulator based on FunctionFS.',
    )
    p.add_argument('-l', '--log-level', type=parse_loglevel, default='INFO', help='Set log level (either Python log level names e.g. DEBUG or numbers e.g. 10).')
    p.add_argument('-k', '--ds4key', required=True, help='Specify DS4Key file.')
    return p, p.parse_args()

def main():
    """
    Entry point.
    """
    _p, args = parse_args()
    logging.basicConfig(level=args.log_level)

    with create_gadget_instance(args) as gadget:
        logger.info('Gadget ready, waiting for function to exit.')
        try:
            gadget.waitForever()
        finally:
            logger.info('Gadget exiting.')

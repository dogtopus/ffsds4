#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This file is part of FFSDS4
# Copyright (C) 2021-  dogtopus

import ctypes
import copy
import contextlib
import enum
import itertools
import io
import logging
import mmap
import time
import threading
import weakref
import zlib # for crc32

from ctypes import c_uint8, c_int16, c_uint16, c_uint32
from typing import Tuple, IO, Iterator, Optional, ByteString, Sequence, Union, Type, MutableSequence, ContextManager, Callable, cast, ClassVar, TypeVar, Protocol, Iterable, BinaryIO
from concurrent import futures

from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Util.number import bytes_to_long

logger = logging.getLogger('ffsds4.ds4')

class ReportType(enum.IntEnum):
    in_report = 0x01
    get_feature_configuration = 0x03
    out_feedback = 0x05
    set_challenge = 0xf0
    get_response = 0xf1
    get_auth_status = 0xf2
    get_auth_page_size = 0xf3


class ButtonType(enum.IntEnum):
    square = 0
    cross = 1
    circle = 2
    triangle = 3
    l1 = 4
    r1 = 5
    l2 = 6
    r2 = 7
    share = 8
    option = 9
    l3 = 10
    r3 = 11
    ps = 12
    touchpad = 13


class DPadPosition(enum.IntFlag):
    neutral = 8
    n = 0
    ne = 1
    e = 2
    se = 3
    s = 4
    sw = 5
    w = 6
    nw = 7


UDCFriendlyBuffer = Union[mmap.mmap, bytearray]
InputTargetType = Union[
    Type[ButtonType],
    Type[DPadPosition],
    str,
]

# Workaround the "mostly broken" ctypes type hints by trying to define a
# compatible interface for ctypes array classes.
# To access ctypes-specific methods on struct member, cast it back to the
# corresponding ctypes.Array[? extends ctypes._CData] type and access. This
# is also loosely applicable to primitive types like ints (in this case cast
# to c_int, etc. instead).
KeyType_contra = TypeVar('KeyType_contra', contravariant=True)
ValType_co = TypeVar('ValType_co')
class Subscriptable(Protocol[KeyType_contra, ValType_co]):
    def __getitem__(self, key: KeyType_contra) -> ValType_co: ...
    def __setitem__(self, key: KeyType_contra, val: ValType_co) -> None: ...

ElementType = TypeVar('ElementType')
class CArrayWrapper(Subscriptable[int, ElementType], Iterable[ElementType]): ...


# Hack for ctypes struct field type
class StructFieldLike:
    offset: int
    size: int


class TouchFrame(ctypes.LittleEndianStructure):
    seq: int
    pos: MutableSequence[int]

    _fields_ = (
        ('seq', c_uint8),
        ('pos', c_uint32 * 2),
    )
    _pack_ = True

    def set_invalidation(self, pos: int, is_invalidate: bool = True):
        if is_invalidate:
            self.pos[pos] |= 1 << 7
        else:
            self.pos[pos] &= (~(1 << 7)) & 0xffffffff

    def validate_pos0(self):
        self.set_invalidation(0, False)

    def invalidate_pos0(self):
        self.set_invalidation(0)

    def validate_pos1(self):
        self.set_invalidation(1, False)

    def invalidate_pos1(self):
        self.set_invalidation(1)

    def get_invalidation(self, pos: int) -> bool:
        return bool(self.pos[pos] >> 7 & 1)

    def get_invalidation_pos0(self) -> bool:
        return self.get_invalidation(0)

    def get_invalidation_pos1(self) -> bool:
        return self.get_invalidation(1)

    def get_invalidation_both(self) -> bool:
        '''
        Return True if both positions are invalidated.
        '''
        return self.get_invalidation_pos0() and self.get_invalidation_pos1()

    def set_pos(self, pos, xy: Tuple[int, int]):
        x, y = xy
        self.pos[pos] = (((y & 0xfff) << 20) | ((x & 0xfff) << 8)) | (self.pos[pos] & 0xff)

    def get_pos(self, pos: int) -> Tuple[int, int]:
        return (self.pos[pos] >> 8) & 0xfff, (self.pos[pos] >> 20) & 0xfff

    def set_pos0(self, xy: Tuple[int, int]):
        self.set_pos(0, xy)

    def set_pos1(self, xy: Tuple[int, int]) -> None:
        self.set_pos(1, xy)

    def set_touch_seq(self, pos: int, seq: int) -> None:
        self.pos[pos] = (self.pos[pos] & 0xffffff80) | (seq & 0x7f)

    def set_touch_seq_pos0(self, seq: int) -> None:
        self.set_touch_seq(0, seq)

    def set_touch_seq_pos1(self, seq: int) -> None:
        self.set_touch_seq(1, seq)

    def get_touch_seq(self, pos: int) -> int:
        return self.pos[pos] & 0x7f

    def get_touch_seq_pos0(self) -> int:
        return self.get_touch_seq(0)

    def get_touch_seq_pos1(self) -> int:
        return self.get_touch_seq(1)

    def clear(self) -> None:
        self.seq = 0
        self.pos[0] = 1 << 7
        self.pos[1] = 1 << 7

class InputReport(ctypes.LittleEndianStructure):
    type: int
    sticks: CArrayWrapper[int]
    buttons: CArrayWrapper[int]
    triggers: CArrayWrapper[int]
    sensor_timestamp: int
    battery: int
    gyro: CArrayWrapper[int]
    accel: CArrayWrapper[int]
    u25: CArrayWrapper[int]
    state_ext: int
    u31: int
    tp_available_frame: int
    tp_frames: CArrayWrapper[TouchFrame]
    padding: CArrayWrapper[int]

    _fields_ = (
        ('type', c_uint8),
        ('sticks', c_uint8 * 4),
        ('buttons', c_uint8 * 3),
        ('triggers', c_uint8 * 2),
        ('sensor_timestamp', c_uint16),
        ('battery', c_uint8),
        ('gyro', c_int16 * 3),
        ('accel', c_int16 * 3),
        ('u25', c_uint8 * 5),
        ('state_ext', c_uint8),
        ('u31', c_uint16),
        ('tp_available_frame', c_uint8),
        ('tp_frames', TouchFrame * 3),
        ('padding', c_uint8 * 3),
    )
    _pack_ = True

    def __init__(self, *args, **kwargs) -> None:
        actual_kwargs = dict(
            type=ReportType.in_report,
            sticks=(0x80, 0x80, 0x80, 0x80),
            state_ext=0x08,
            battery=0xff,
        )
        actual_kwargs.update(kwargs)
        super().__init__(*args, **actual_kwargs)
        self.set_dpad(DPadPosition.neutral)
        self.clear_touchpad()

    def inc_report_index(self) -> None:
        '''
        Increment the report index.
        '''
        self.buttons[2] += 4

    def clear_report_index(self) -> None:
        self.buttons[2] ^= self.buttons[2] & 0b11111100

    def set_button(self, button: Union[int, ButtonType], pressed: bool) -> None:
        button = ButtonType(button)
        button = int(button) + 4
        byte_offset = ((button >> 3) & 3)
        bit_offset = button & 7
        if pressed:
            self.buttons[byte_offset] |= 1 << bit_offset
        else:
            self.buttons[byte_offset] &= (~(1 << bit_offset)) & 0xff

    def clear_buttons(self) -> None:
        self.buttons[0] ^= self.buttons[0] & 0b00001111
        self.buttons[1] = 0
        self.buttons[2] = 0

    def set_stick(self, left: Tuple[int, int], right: Tuple[int, int]) -> None:
        self.sticks[0] = left[0]
        self.sticks[1] = left[1]
        self.sticks[2] = right[0]
        self.sticks[3] = right[1]

    def set_dpad(self, position: DPadPosition) -> None:
        position = DPadPosition(position)
        self.buttons[0] ^= self.buttons[0] & 0xf
        self.buttons[0] |= int(position)

    def clear_touchpad(self) -> None:
        self.tp_available_frame = 0
        for frame in self.tp_frames:
            frame.clear()


class FeedbackReport(ctypes.LittleEndianStructure):
    type: int
    flags: int
    padding1: CArrayWrapper[int]
    rumble_right: int
    rumble_left: int
    led_color: CArrayWrapper[int]
    led_flash_on: int
    led_flash_off: int
    padding: CArrayWrapper[int]

    _fields_ = (
        ('type', c_uint8),
        ('flags', c_uint8),
        ('padding1', c_uint8 * 2),
        ('rumble_right', c_uint8),
        ('rumble_left', c_uint8),
        ('led_color', c_uint8 * 3),
        ('led_flash_on', c_uint8),
        ('led_flash_off', c_uint8),
        ('padding', c_uint8 * 21),
    )
    _pack_ = True

    # TODO feedback related


# Mostly educated guesses.
class IMUParameters(ctypes.LittleEndianStructure):
    gyro_range: int
    gyro_res_per_deg_s_denom: int
    gyro_res_per_deg_s_num: int
    accel_range: int
    acc_res_per_g: int

    _fields_ = (
        ('gyro_range', c_uint16),
        ('gyro_res_per_deg_s_denom', c_uint16),
        ('gyro_res_per_deg_s_num', c_uint16),
        ('accel_range', c_uint16),
        ('acc_res_per_g', c_uint16),
    )
    _pack_ = True


class ControllerType(enum.IntEnum):
    main_controller = 0x00
    guitar = 0x01
    steering_wheel = 0x06


class ControllerFeature(enum.IntFlag):
    unk_bit0 = 1
    motion = 1 << 1
    feedback_led = 1 << 2
    rumble = 1 << 3
    unk_bit4 = 1 << 4
    unk_bit5 = 1 << 5
    touchpad = 1 << 6
    unk_bit7 = 1 << 7


class FeatureConfiguration(ctypes.LittleEndianStructure):
    type: int
    hid_usage: int
    u3: int
    features: Union[int, ControllerFeature]
    controller_type: Union[int, ControllerType]
    touchpad_param: CArrayWrapper[int]
    imu_param: IMUParameters
    magic_0x0d0d: int
    u20: CArrayWrapper[int]
    wheel_param: CArrayWrapper[int]
    u27: CArrayWrapper[int]

    _fields_ = (
        ('type', c_uint8),
        ('hid_usage', c_uint16),
        ('u3', c_uint8),
        ('features', c_uint8),
        ('controller_type', c_uint8),
        ('touchpad_param', c_uint8 * 2),
        ('imu_param', IMUParameters),
        ('magic_0x0d0d', c_uint16),
        ('u20', c_uint8 * 4),
        ('wheel_param', c_uint8 * 3),
        ('u27', c_uint8 * 21),
    )
    _pack_ = True

    def __init__(self,
                 enable_touchpad=False,
                 enable_imu=False,
                 enable_led=False,
                 enable_rumble=False,
                 ctypes_args=[],
                 ctypes_kwargs={}):
        self.features = 0
        actual_kwargs = dict(
            type=ReportType.get_feature_configuration,
            hid_usage=0x2721,
            magic_0x0d0d=0x0d0d,
        )
        actual_kwargs.update(ctypes_kwargs)
        super().__init__(*ctypes_args, **actual_kwargs)

        # This seems to be (almost) always enabled
        self.features |= ControllerFeature.unk_bit0
        # Default controller type is main controller or DS4 replacement
        self.controller_type = ControllerType.main_controller
        # This can be either 0x03 or 0x04 but most of them are 0x04
        self.u3 = 0x04

        self.enable_touchpad(enable_touchpad)
        self.enable_imu(enable_imu)
        self.enable_led(enable_led)
        self.enable_rumble(enable_rumble)

    def enable_touchpad(self, enabled: bool):
        if enabled:
            self.features |= ControllerFeature.touchpad
            self.touchpad_param[0] = 0x2c
            self.touchpad_param[1] = 0x56
        else:
            self.features &= (~ControllerFeature.touchpad) & 0xff
            self.touchpad_param[0] = 0x0
            self.touchpad_param[1] = 0x0

    def enable_imu(self, enabled: bool):
        if enabled:
            self.features |= ControllerFeature.motion
            self.imu_param.gyro_range = 4000
            self.imu_param.gyro_res_per_deg_s_denom = 61
            self.imu_param.gyro_res_per_deg_s_num = 1000
            self.imu_param.accel_range = 1
            self.imu_param.acc_res_per_g = 8192
        else:
            self.features &= (~ControllerFeature.motion) & 0xff
            self.imu_param.gyro_range = 0
            self.imu_param.gyro_res_per_deg_s_denom = 0
            self.imu_param.gyro_res_per_deg_s_num = 0
            self.imu_param.accel_range = 0
            self.imu_param.acc_res_per_g = 0

    def enable_led(self, enabled: bool):
        if enabled:
            self.features |= ControllerFeature.feedback_led
        else:
            self.features &= (~ControllerFeature.feedback_led) & 0xff

    def enable_rumble(self, enabled: bool):
        if enabled:
            if self.features & ControllerFeature.feedback_led == 0:
                logger.warning('Rumble implies LED report but it is not enabled. Enabling it.')
                self.features |= ControllerFeature.feedback_led
            self.features |= ControllerFeature.rumble
        else:
            self.features &= (~ControllerFeature.rumble) & 0xff


class AuthPageSizeReport(ctypes.LittleEndianStructure):
    type: int
    u1: int
    size_challenge: int
    size_response: int
    u4: CArrayWrapper[int]

    _fields_ = (
        ('type', c_uint8),
        ('u1', c_uint8),
        ('size_challenge', c_uint8),
        ('size_response', c_uint8),
        ('u4', c_uint8 * 4),
    )
    _pack_ = True


class AuthReport(ctypes.LittleEndianStructure):
    type: int
    seq: int
    page: int
    sbz: int
    data: ctypes.Array[c_uint8] # not exactly but close enough
    crc32: int

    _fields_ = (
        ('type', c_uint8),
        ('seq', c_uint8),
        ('page', c_uint8),
        ('sbz', c_uint8),
        ('data', c_uint8 * 56),
        ('crc32', c_uint32),
    )
    _pack = True


class AuthStatusReport(ctypes.LittleEndianStructure):
    type: int
    seq: int
    status: int
    padding: CArrayWrapper[int]
    crc32: int

    _fields_ = (
        ('type', c_uint8),
        ('seq', c_uint8),
        ('status', c_uint8),
        ('padding', c_uint8 * 9),
        ('crc32', c_uint32),
    )
    _pack = True


class DS4IdentityBlock(ctypes.LittleEndianStructure):
    serial: ctypes.Array[c_uint8]
    modulus: ctypes.Array[c_uint8]
    exponent: ctypes.Array[c_uint8]

    _pack_ = 1
    _fields_ = (
        ('serial', c_uint8 * 0x10),
        ('modulus', c_uint8 * 0x100),
        ('exponent', c_uint8 * 0x100),
    )


class DS4PrivateKeyBlock(ctypes.LittleEndianStructure):
    p: ctypes.Array[c_uint8]
    q: ctypes.Array[c_uint8]
    dp1: ctypes.Array[c_uint8]
    dq1: ctypes.Array[c_uint8]
    pq: ctypes.Array[c_uint8]

    _pack_ = 1
    _fields_ = (
        ('p', c_uint8 * 0x80),
        ('q', c_uint8 * 0x80),
        ('dp1', c_uint8 * 0x80),
        ('dq1', c_uint8 * 0x80),
        ('pq', c_uint8 * 0x80),
    )


class DS4SignedIdentityBlock(ctypes.LittleEndianStructure):
    identity: DS4IdentityBlock
    sig_identity: ctypes.Array[c_uint8]

    _pack_ = 1
    _fields_ = (
        ('identity', DS4IdentityBlock),
        ('sig_identity', c_uint8 * 0x100),
    )


class DS4FullKeyBlock(ctypes.LittleEndianStructure):
    identity: DS4IdentityBlock
    sig_identity: ctypes.Array[c_uint8]
    private_key: DS4PrivateKeyBlock

    _pack_ = 1
    _fields_ = (
        ('identity', DS4IdentityBlock),
        ('sig_identity', c_uint8 * 0x100),
        ('private_key', DS4PrivateKeyBlock),
    )


class DS4Response(ctypes.LittleEndianStructure):
    sig: ctypes.Array[c_uint8]
    signed_identity: DS4SignedIdentityBlock

    _pack_ = 1
    _fields_ = (
        ('sig', c_uint8 * 0x100),
        ('signed_identity', DS4SignedIdentityBlock),
    )


AUTH_REQ_SIZE = 0x100
AUTH_RESP_SIZE = 0x410


class DS4Key:
    def __init__(self, ds4key_file: BinaryIO) -> None:
        ds4key = DS4FullKeyBlock()
        actual = ds4key_file.readinto(ds4key) #type: ignore
        if actual != ctypes.sizeof(DS4FullKeyBlock):
            raise ValueError('DS4Key too small.')

        n = bytes_to_long(bytes(ds4key.identity.modulus))
        e = bytes_to_long(bytes(ds4key.identity.exponent))
        p = bytes_to_long(bytes(ds4key.private_key.p))
        q = bytes_to_long(bytes(ds4key.private_key.q))
        dp1 = bytes_to_long(bytes(ds4key.private_key.dp1))
        dq1 = bytes_to_long(bytes(ds4key.private_key.dq1))
        pq = bytes_to_long(bytes(ds4key.private_key.pq))

        d = Integer(e).inverse((p-1) * (q-1)) #type: ignore[call-arg]
        pq_from_pq = Integer(q).inverse(p) #type: ignore[call-arg]
        dp1_from_pq = Integer(d) % (p-1) #type: ignore[call-arg]
        dq1_from_pq = Integer(d) % (q-1) #type: ignore[call-arg]
        if Integer(pq) != pq_from_pq or Integer(dp1) != dp1_from_pq or Integer(dq1) != dq1_from_pq: #type: ignore[call-arg]
            raise ValueError('Bad key block (CRT factors inconsistent with P and Q)')

        # TODO broken type tagging in pycryptodome. Should we fix it upstream?
        key = RSA.construct((n, e, d, p, q), consistency_check=True) #type: ignore[arg-type]
        fppub = SHA256.new(key.publickey().exportKey('DER')).hexdigest()
        fppriv = SHA256.new(key.exportKey('DER')).hexdigest()

        self._key = key
        self._pss = pss.new(self._key)
        self._ds4id = DS4SignedIdentityBlock()
        self._ds4id.identity = ds4key.identity
        self._ds4id.sig_identity = ds4key.sig_identity

        logger.info('DS4Key loaded fingerprint=%s, private_fingerprint=%s', fppub, fppriv)

    def sign_challenge(self, challenge: bytes) -> DS4Response:
        sha = SHA256.new(challenge)
        sig = self._pss.sign(sha)

        buf = DS4Response()
        ctypes.memmove(buf.sig, sig, cast(StructFieldLike, DS4Response.sig).size)
        buf.signed_identity = self._ds4id
        return buf


# OK Java code
# Also f*** all Python IDEs. Yes, all of them >(.
class ReportModificationContext(ContextManager[InputReport]):
    def __init__(self, tracker: "DS4StateTracker") -> None:
        self._tracker = tracker

    def __enter__(self) -> InputReport:
        self._tracker.input_report_lock.acquire()
        return self._tracker.input_report_writable

    def __exit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        self._tracker.input_report_lock.release()


class DS4TouchStateTracker:
    def __init__(self, parent: 'DS4StateTracker'):
        self._tp_touch_autoindex = 0
        self._last_known_tp_frame = TouchFrame()
        self._last_known_tp_frame.clear()
        self._parent = weakref.proxy(parent)

    def _get_touch_autoindex(self) -> int:
        rv = self._tp_touch_autoindex
        self._tp_touch_autoindex += 1
        self._tp_touch_autoindex &= 0x7f
        return rv

    def queue_touchpad_sustain(self):
        with self._parent.start_modify_report() as report:
            self._queue_touchpad_sustain(report)

    def _queue_touchpad_sustain(self, report: InputReport):
        '''
        Queue last touchpad position if it is valid and there is no other
        frames queued.

        Should be called right before submitting the buffer.
        '''
        if report.tp_available_frame == 0:
            if not self._last_known_tp_frame.get_invalidation_both():
                self._last_known_tp_frame.seq += 1
            report.tp_frames[0] = self._last_known_tp_frame
            report.tp_available_frame += 1

    def queue_touchpad(self, pos0: Optional[Tuple[int, int]] = None, pos1: Optional[Tuple[int, int]] = None, release_pos0: bool = True, release_pos1: bool = True) -> None:
        '''
        Queue touchpad press.

        If pos0 and pos1 are 2-tuple of ints, they are used as the new
        coordinates of the touch. If they are None, release_pos0 and
        release_pos1 will be checked. If they are True, the corresponding
        points are released (invalidated), otherwise the points will remain
        unchanged (held down).
        '''

        with self._parent.start_modify_report() as report:
            self._queue_touchpad(report, pos0, pos1, release_pos0, release_pos1)

    def _queue_touchpad(self, report: InputReport, pos0: Optional[Tuple[int, int]] = None, pos1: Optional[Tuple[int, int]] = None, release_pos0: bool = True, release_pos1: bool = True) -> None:
        if report.tp_available_frame >= 3:
            raise RuntimeError('Touchpad frame queue full.')

        frame = self._last_known_tp_frame

        frame.seq += 1

        if pos0 is not None:
            frame.set_pos0(pos0)
            # Validate the touch position if it's previously invalidated and increment the touch counter
            if frame.get_invalidation_pos0():
                frame.set_touch_seq_pos0(self._get_touch_autoindex())
                frame.validate_pos0()
        elif release_pos0:
            # Release the touch when required
            frame.invalidate_pos0()
        # Otherwise, do nothing (lazy update)

        if pos1 is not None:
            frame.set_pos1(pos1)
            if frame.get_invalidation_pos1():
                frame.set_touch_seq_pos1(self._get_touch_autoindex())
                frame.validate_pos1()
        elif release_pos1:
            frame.invalidate_pos1()

        # Copy last working frame to the report
        report.tp_frames[report.tp_available_frame] = frame
        report.tp_available_frame += 1


class DS4IMUStateTracker:
    _position: Tuple[float, float, float]
    _attitude: Tuple[float, float, float]
    def __init__(self, parent: 'DS4StateTracker', get_current_time: Callable[[], float] = time.monotonic):
        self._parent = weakref.proxy(parent)
        self._sustain = True
        self._use_attitude_position = False

        self._get_current_time = get_current_time

        self._time_base = self._get_current_time()
        self._time = self._time_base

        # Coordinates in right-hand coordination system
        self._position = (0.0, 0.0, 0.0) # x, y, z
        self._attitude = (0.0, 0.0, 0.0) # pitch, yaw, roll
        # Position and attitude, integrated back from downsampled integer samples (for compensation)
        #self._position_int = [0.0, 0.0, 0.0]
        #self._attitude_int = [0.0, 0.0, 0.0]

        self._motion_s_to_timestamp_mult = 187500 # 1000 * 3000 / 16
        # Hardcode this for now for further calibration
        self._max_deg_per_s = 4000
        self._res_per_deg_per_s = 1000 / 61
        self._accel_res_per_g = 8192

    def reset_time(self):
        self._time_base = self._get_current_time()
        self._time = self._time_base

    @property
    def use_attitude_position(self):
        return self._use_attitude_position

    @use_attitude_position.setter
    def use_attitude_position(self, val: bool):
        # TODO trigger controller attitude and position reset
        self._use_attitude_position = val

    def _convert_angular_velocity(self, name: str, value: float) -> int:
        '''
        Convert angular velocity from deg/s to internal integer representation.
        '''
        rv = round(self._res_per_deg_per_s * value)
        if rv < -32768 or rv > 32767:
            raise ValueError(f'Angular velocity for {name} out of range (expecting approx. ({-32768/self._res_per_deg_per_s:.4f}, {32767/self._res_per_deg_per_s:.4f}), got {value})')
        return rv

    def _convert_linear_acceleration(self, name: str, value: float) -> int:
        '''
        Convert linear acceleration from g (*9.8m/s^2) to internal integer representation.
        '''
        rv = round(self._accel_res_per_g * value)
        if rv < -32768 or rv > 32767:
            raise ValueError(f'Linear acceleration for {name} axis out of range (expecting approx. ({-32768/self._accel_res_per_g:.4f}, {32767/self._accel_res_per_g:.4f}), got {value})')
        return rv

    def set_angular_velocity(self, pitch: Optional[float] = None, yaw: Optional[float] = None, roll: Optional[float] = None):
        '''
        Set raw angular velocity (in deg/s).
        '''
        if self._use_attitude_position:
            raise RuntimeError('Cannot set angular velocity in attitude-position mode.')
        self._set_angular_velocity(pitch, yaw, roll)

    def _set_angular_velocity(self, pitch: Optional[float] = None, yaw: Optional[float] = None, roll: Optional[float] = None):
        pitch_in_res: Optional[int] = None
        yaw_in_res: Optional[int] = None
        roll_in_res: Optional[int] = None

        if pitch is not None:
            pitch_in_res = self._convert_angular_velocity('pitch', pitch)
        if yaw is not None:
            yaw_in_res = self._convert_angular_velocity('yaw', yaw)
        if roll is not None:
            roll_in_res = self._convert_angular_velocity('roll', roll)

        with self._parent.start_modify_report() as report:
            if pitch_in_res is not None:
                report.gyro[0] = pitch_in_res
            if yaw_in_res is not None:
                report.gyro[1] = yaw_in_res
            if roll_in_res is not None:
                report.gyro[2] = roll_in_res

    def set_linear_acceleration(self, x: Optional[float] = None, y: Optional[float] = None, z: Optional[float] = None):
        '''
        Set raw linear acceleration (in g).
        '''
        if self._use_attitude_position:
            raise RuntimeError('Cannot set angular velocity in attitude-position mode.')
        self._set_linear_acceleration(x, y, z)

    def _set_linear_acceleration(self, x: Optional[float] = None, y: Optional[float] = None, z: Optional[float] = None):
        x_in_res: Optional[int] = None
        y_in_res: Optional[int] = None
        z_in_res: Optional[int] = None
        if x is not None:
            x_in_res = self._convert_linear_acceleration('x', x)
        if y is not None:
            y_in_res = self._convert_linear_acceleration('y', y)
        if z is not None:
            z_in_res = self._convert_linear_acceleration('z', z)

        with self._parent.start_modify_report() as report:
            if x is not None:
                report.accel[0] = x_in_res
            if y is not None:
                report.accel[1] = y_in_res
            if z is not None:
                report.accel[2] = z_in_res

    def set_attitude_position(self, current_time: float,
                                    pitch: Optional[float] = None,
                                    yaw: Optional[float] = None,
                                    roll: Optional[float] = None,
                                    x: Optional[float] = None,
                                    y: Optional[float] = None,
                                    z: Optional[float] = None):
        '''
        Set the current attitude (in deg) and position (in mm) and the current
        timestamp (must be monotonic). Intended to be driven by tween objects
        from the sequencer to simulate real IMU.

        Usually it's the tweens' responsibility to figure out the current time
        in order to minimize jitter. Therefore the time must be specified by
        the caller (e.g. tweens).
        '''
        difference = current_time - self._time
        if difference < 0:
            raise ValueError('current_time must be monotonic.')

        curr_attitude: Tuple[float, float, float] = (
            pitch if pitch is not None else self._attitude[0],
            yaw if yaw is not None else self._attitude[1],
            roll if roll is not None else self._attitude[2],
        )
        curr_position: Tuple[float, float, float] = (
            x if x is not None else self._position[0],
            y if y is not None else self._position[1],
            z if z is not None else self._position[2],
        )
        diff_attitude: Tuple[float, float, float] = cast(Tuple[float, float, float], tuple((curr - prev) / difference for curr, prev in zip(curr_attitude, self._attitude)))
        # mm/s^2 to g: / 9.8 m/s^2 / 1000mm/m
        diff2_position: Tuple[float, float, float] = cast(Tuple[float, float, float], tuple((curr - prev) / difference**2 / 9.8 / 1000 for curr, prev in zip(curr_position, self._position)))
        # TODO add gravity and compensation for rounding errors
        diff_p, diff_y, diff_r = diff_attitude
        diff2_x, diff2_y, diff2_z = diff2_position

        # Acquire the RLock here so the change happens atomically (no out of sync gyro/accel reports)
        with self._parent.start_modify_report() as report:
            self._set_angular_velocity(diff_p, diff_y, diff_r)
            self._set_linear_acceleration(diff2_x, diff2_y, diff2_z)
            report.sensor_timestamp = round((current_time - self._time_base) * self._motion_s_to_timestamp_mult) & 0xffff
            # Clear the sustain bit
            self._sustain = False

        self._attitude = curr_attitude
        self._position = curr_position
        self._time = current_time

    def get_attitude_position(self) -> Tuple[float, float, float, float, float, float, float]:
        return (
            self._time,
            self._attitude[0], self._attitude[1], self._attitude[2],
            self._position[0], self._position[1], self._position[2],
        )

    def set_attitude_position_sustain(self) -> None:
        if not self._use_attitude_position:
            # Does noting when not in attitude-position mode.
            return

        # Acquire lock to make sure we're not doing a sustain during an IMU report update (from e.g. the sequencer).
        with self._parent.start_modify_report():
            if self._sustain:
                self.set_attitude_position(self._get_current_time())

            # Set the sustain bit.
            self._sustain = True


class DS4AuthStateTracker:
    def __init__(self, ds4key: DS4Key):
        self._ds4key = ds4key
        self._nonce = io.BytesIO()
        self._response = io.BytesIO()
        self._status = 0x10
        self._seq = 0
        self._req_page = 0
        self._resp_page = 0
        self._req_size = cast(StructFieldLike, AuthReport.data).size
        self._resp_size = cast(StructFieldLike, AuthReport.data).size
        self._req_max_page = -(-AUTH_REQ_SIZE // self._req_size) - 1
        self._resp_max_page = -(-AUTH_RESP_SIZE // self._req_size) - 1
        self._rsa_task = futures.ThreadPoolExecutor()

    @property
    def req_size(self) -> int:
        return self._req_size

    @req_size.setter
    def req_size(self, val: int) -> None:
        if val > cast(StructFieldLike, AuthReport.data).size:
            raise ValueError('Data size too big')
        self._req_size = val
        self._req_max_page = -(-AUTH_REQ_SIZE // val) - 1

    @property
    def resp_size(self) -> int:
        return self._resp_size

    @resp_size.setter
    def resp_size(self, val) -> None:
        if val > cast(StructFieldLike, AuthReport.data).size:
            raise ValueError('Data size too big')
        self._resp_size = val
        self._resp_max_page = -(-AUTH_RESP_SIZE // val) - 1

    def reset(self) -> None:
        self._status = 0x10
        self._req_page = 0
        self._resp_page = 0
        self._nonce.seek(0)
        self._response.seek(0)
        self._nonce.truncate(0)
        self._response.truncate(0)

    def prepare_challenge(self) -> None:
        try:
            self._response.write(self._ds4key.sign_challenge(self._nonce.getvalue())) #type: ignore[arg-type]
            self._response.seek(0)
        except Exception:
            logger.exception('Challenge signing failed with an exception.')
            # TODO
            self._status = 0xff
        else:
            self._status = 0x0

    def get_page_size(self, ep0: io.FileIO) -> None:
        buf = AuthPageSizeReport(type=ReportType.get_auth_page_size)
        buf.size_challenge = self.req_size
        buf.size_response = self.resp_size
        ep0.write(buf) #type: ignore[arg-type]

    def set_challenge(self, ep0: io.FileIO) -> None:
        buf = AuthReport()
        ep0.readinto(buf) #type: ignore[arg-type]
        crc = zlib.crc32(bytes(buf)[:ctypes.sizeof(AuthReport) - ctypes.sizeof(c_uint32)])
        if crc != buf.crc32:
            # TODO do we need to do more here?
            logger.warning("Invalid CRC32.")
        if buf.type != int(ReportType.set_challenge):
            raise TypeError('Invalid request type for request set_challenge.')
        if buf.page != 0 and buf.seq != self._seq:
            logger.warning("Inconsistent sequence value.")
        elif buf.page != self._req_page:
            logger.warning("Out of order challenge write.")
        self._seq = buf.seq
        valid_data_size = min(max(0, AUTH_REQ_SIZE - buf.page * self._req_size), self._req_size)
        self._nonce.write(memoryview(cast(bytearray, buf.data))[:valid_data_size]) # bytearray-like
        if self._req_page == self._req_max_page:
            self._status = 0x01
            self._rsa_task.submit(self.prepare_challenge)
        self._req_page += 1

    def get_status(self, ep0: io.FileIO) -> None:
        buf = AuthStatusReport(type=ReportType.get_auth_status)
        buf.seq = self._seq
        buf.status = self._status
        buf.crc32 = zlib.crc32(bytes(buf)[:ctypes.sizeof(AuthStatusReport) - ctypes.sizeof(c_uint32)])
        ep0.write(buf) #type: ignore[arg-type]

    def get_response(self, ep0: io.FileIO) -> None:
        buf = AuthReport(type=ReportType.get_response)
        buf.seq = self._seq
        buf.page = self._resp_page
        if self._response.readinto(cast(bytearray, buf.data)) == 0: # bytearray-like
            logger.warning('Attempt to read outside of the auth response buffer.')
        if self._resp_page == self._resp_max_page:
            self.reset()
        buf.crc32 = zlib.crc32(bytes(buf)[:ctypes.sizeof(AuthReport) - ctypes.sizeof(c_uint32)])
        ep0.write(buf) #type: ignore[arg-type]
        if self._status == 0x0:
            self._resp_page += 1


class DS4StateTracker:
    _input_report_bufa: UDCFriendlyBuffer
    _input_report_bufb: UDCFriendlyBuffer
    def __init__(self, ds4key: DS4Key, features: FeatureConfiguration, aligned: bool = False, imu_time_func: Optional[Callable[[], float]] = None) -> None:
        if aligned:
            # Use report constructor to create a template
            report_template = bytes(InputReport())
            # Allocate buffers to page boundary
            self._input_report_bufa = mmap.mmap(-1, 64)
            self._input_report_bufb = mmap.mmap(-1, 64)
            # Copy the template over
            self._input_report_bufa.write(report_template)
            self._input_report_bufb.write(report_template)
            self._input_report_bufa.seek(0)
            self._input_report_bufb.seek(0)
        else:
            # Initialize report A (use the constructor to fill in the initial fields)
            self._input_report_bufa = bytearray(InputReport())
            # Initialize report B as well
            self._input_report_bufb = bytearray(InputReport())

        # Bind buffer A to a new report object (Note this will not copy Python objects over)
        self._input_report_a = InputReport.from_buffer(memoryview(self._input_report_bufa))
        logger.debug('Buffer A: %s', hex(ctypes.addressof(self._input_report_a)))

        # Bind buffer B to a new report object (Note this will not copy Python objects over)
        self._input_report_b = InputReport.from_buffer(memoryview(self._input_report_bufb))
        logger.debug('Buffer B: %s', hex(ctypes.addressof(self._input_report_b)))

        # Set current sending and next report references
        self._input_report_submitting = self._input_report_a
        self._input_report_writable = self._input_report_b
        self._input_report_submitting_buf = self._input_report_bufa
        self._input_report_writable_buf = self._input_report_bufb

        # Create input report lock
        self.input_report_lock = threading.RLock()

        # Create dummy feedback report
        self.feedback_report = FeedbackReport()

        # Initialize auth state tracker
        self._auth = DS4AuthStateTracker(ds4key)

        # Initialize feature configuration
        self._features = features

        self._touch = DS4TouchStateTracker(self)
        self._imu = DS4IMUStateTracker(self, get_current_time=time.monotonic if imu_time_func is None else imu_time_func)

    @property
    def input_report_writable(self) -> InputReport:
        return self._input_report_writable

    @property
    def input_report_submitting(self) -> InputReport:
        return self._input_report_submitting

    @property
    def input_report_writable_buf(self) -> UDCFriendlyBuffer:
        return self._input_report_writable_buf

    @property
    def input_report_submitting_buf(self) -> UDCFriendlyBuffer:
        return self._input_report_submitting_buf

    @property
    def auth(self) -> DS4AuthStateTracker:
        return self._auth

    @property
    def touch(self) -> DS4TouchStateTracker:
        return self._touch

    @property
    def imu(self) -> DS4IMUStateTracker:
        return self._imu

    def swap_buffer(self) -> None:
        with self.input_report_lock:
            self.swap_buffer_nolock()

    def swap_buffer_nolock(self) -> None:
        self._input_report_submitting, self._input_report_writable = self._input_report_writable, self._input_report_submitting
        self._input_report_submitting_buf, self._input_report_writable_buf = self._input_report_writable_buf, self._input_report_submitting_buf

    def sync_buffer(self) -> None:
        with self.input_report_lock:
            self.sync_buffer_nolock()

    def sync_buffer_nolock(self) -> None:
        ctypes.pointer(self._input_report_writable)[0] = self._input_report_submitting

    def start_modify_report(self) -> ReportModificationContext:
        return ReportModificationContext(self)

    def prepare_for_report_submission(self) -> UDCFriendlyBuffer:
        with self.input_report_lock:
            # Queue the last touchpad points if applicable (for touchpad holding).
            self._touch.queue_touchpad_sustain()
            self._imu.set_attitude_position_sustain()
            # Swap and copy the buffer.
            self.swap_buffer_nolock()
            self.sync_buffer_nolock()
            # After copying, increment the report index of the writable buffer.
            self.input_report_writable.inc_report_index()
            # Also clear the touchpad buffer
            self.input_report_writable.clear_touchpad()
        return self.input_report_submitting_buf

    def process_feedback(self, data: memoryview) -> None:
        if len(data) != ctypes.sizeof(FeedbackReport):
            logger.error('Wrong size for feedback report. Ignored')
            return None
        self.feedback_report = FeedbackReport.from_buffer_copy(data)

    def get_feature_configuration(self, ep0: io.FileIO) -> None:
        ep0.write(self._features) #type: ignore[arg-type]


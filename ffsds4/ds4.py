#!/usr/bin/env python3

import ctypes
import copy
import contextlib
import enum
import itertools
import io
import logging
import threading
from typing import Tuple, IO, Iterator, Optional, ByteString, Sequence, Union, Type
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


InputTargetType = Union[
    Type[ButtonType],
    Type[DPadPosition],
    str,
]


class TouchFrame(ctypes.LittleEndianStructure):
    seq: int
    pos: Sequence[int]

    _fields_ = (
        ('seq', ctypes.c_uint8),
        ('pos', ctypes.c_uint32 * 2),
    )
    _pack_ = True


class InputReport(ctypes.LittleEndianStructure):
    type: int
    sticks: ByteString
    buttons: ByteString
    triggers: ByteString
    sensor_timestamp: int
    battery: int
    u13: int
    gyro: Sequence[int]
    accel: Sequence[int]
    u26: int
    state_ext: int
    u31: int
    tp_available_frame: int
    tp_frames: Sequence[TouchFrame]
    padding: ByteString

    _fields_ = (
        ('type', ctypes.c_uint8),
        ('sticks', ctypes.c_uint8 * 4),
        ('buttons', ctypes.c_uint8 * 3),
        ('triggers', ctypes.c_uint8 * 2),
        ('sensor_timestamp', ctypes.c_uint16),
        ('battery', ctypes.c_uint8),
        ('u13', ctypes.c_uint8),
        ('gyro', ctypes.c_int16 * 3),
        ('accel', ctypes.c_int16 * 3),
        ('u26', ctypes.c_uint32),
        ('state_ext', ctypes.c_uint8),
        ('u31', ctypes.c_uint16),
        ('tp_available_frame', ctypes.c_uint8),
        ('tp_frames', TouchFrame * 3),
        ('padding', ctypes.c_uint8 * 3),
    )
    _pack_ = True

    def __init__(self, *args, **kwargs):
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

    def set_button(self, button: ButtonType, pressed: bool):
        button = ButtonType(button)
        button = int(button) + 4
        byte_offset = ((button >> 3) & 3)
        bit_offset = button & 7
        if pressed:
            self.buttons[byte_offset] |= 1 << bit_offset
        else:
            self.buttons[byte_offset] &= (~(1 << bit_offset)) & 0xff

    def clear_buttons(self):
        self.buttons[0] ^= self.buttons[0] & 0b00001111
        self.buttons[1] = 0
        self.buttons[2] = 0

    def set_stick(self, left: Tuple[int, int], right: Tuple[int, int]):
        self.sticks[0] = left[0]
        self.sticks[1] = left[1]
        self.sticks[2] = right[0]
        self.sticks[3] = right[1]

    def set_dpad(self, position: DPadPosition):
        position = DPadPosition(position)
        self.buttons[0] ^= self.buttons[0] & 0xf
        self.buttons[0] |= int(position)

    # TODO IMU and touchpad

    def clear_touchpad(self):
        self.tp_available_frame = 0
        for i in range(3):
            self.tp_frames[i].seq = 0
            self.tp_frames[i].pos[0] = 1 << 7
            self.tp_frames[i].pos[1] = 1 << 7


class FeedbackReport(ctypes.LittleEndianStructure):
    type: int
    flags: int
    padding1: ByteString
    rumble_right: int
    rumble_left: int
    led_color: ByteString
    led_flash_on: int
    led_flash_off: int
    padding: ByteString

    _fields_ = (
        ('type', ctypes.c_uint8),
        ('flags', ctypes.c_uint8),
        ('padding1', ctypes.c_uint8 * 2),
        ('rumble_right', ctypes.c_uint8),
        ('rumble_left', ctypes.c_uint8),
        ('led_color', ctypes.c_uint8 * 3),
        ('led_flash_on', ctypes.c_uint8),
        ('led_flash_off', ctypes.c_uint8),
        ('padding', ctypes.c_uint8 * 21),
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
        ('gyro_range', ctypes.c_uint16),
        ('gyro_res_per_deg_s_denom', ctypes.c_uint16),
        ('gyro_res_per_deg_s_num', ctypes.c_uint16),
        ('accel_range', ctypes.c_uint16),
        ('acc_res_per_g', ctypes.c_uint16),
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
    magic_0x2721: int
    u3: int
    features: Union[int, ControllerFeature]
    controller_type: Union[int, ControllerType]
    touchpad_param: ByteString
    imu_param: IMUParameters
    magic_0x0d0d: int
    u20: ByteString
    wheel_param: ByteString
    u27: ByteString

    _fields_ = (
        ('type', ctypes.c_uint8),
        ('magic_0x2721', ctypes.c_uint16),
        ('u3', ctypes.c_uint8),
        ('features', ctypes.c_uint8),
        ('controller_type', ctypes.c_uint8),
        ('touchpad_param', ctypes.c_uint8 * 2),
        ('imu_param', IMUParameters),
        ('magic_0x0d0d', ctypes.c_uint16),
        ('u20', ctypes.c_uint8 * 4),
        ('wheel_param', ctypes.c_uint8 * 3),
        ('u27', ctypes.c_uint8 * 21),
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
            u3=0x04,
            # This seems to be always enabled
            features=ControllerFeature.unk_bit0,
            # TODO how to properly break this out
            controller_type=ControllerType.main_controller,
            magic_0x2721=0x2721,
            magic_0x0d0d=0x0d0d,
        )
        actual_kwargs.update(ctypes_kwargs)
        super().__init__(*ctypes_args, **actual_kwargs)

        self.features |= ControllerFeature.unk_bit0
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
    _fields_ = (
        ('type', ctypes.c_uint8),
        ('u1', ctypes.c_uint8),
        ('size_challenge', ctypes.c_uint8),
        ('size_response', ctypes.c_uint8),
        ('u4', ctypes.c_uint8 * 4),
    )
    _pack_ = True


class AuthReport(ctypes.LittleEndianStructure):
    _fields_ = (
        ('type', ctypes.c_uint8),
        ('seq', ctypes.c_uint8),
        ('page', ctypes.c_uint8),
        ('sbz', ctypes.c_uint8),
        ('data', ctypes.c_uint8 * 56),
        ('crc32', ctypes.c_uint32),
    )
    _pack = True


class AuthStatusReport(ctypes.LittleEndianStructure):
    _fields_ = (
        ('type', ctypes.c_uint8),
        ('seq', ctypes.c_uint8),
        ('status', ctypes.c_uint8),
        ('padding', ctypes.c_uint8 * 9),
        ('crc32', ctypes.c_uint32),
    )
    _pack = True


class DS4IdentityBlock(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('serial', ctypes.c_uint8 * 0x10),
        ('modulus', ctypes.c_uint8 * 0x100),
        ('exponent', ctypes.c_uint8 * 0x100),
    )


class DS4PrivateKeyBlock(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('p', ctypes.c_uint8 * 0x80),
        ('q', ctypes.c_uint8 * 0x80),
        ('dp1', ctypes.c_uint8 * 0x80),
        ('dq1', ctypes.c_uint8 * 0x80),
        ('pq', ctypes.c_uint8 * 0x80),
    )


class DS4SignedIdentityBlock(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('identity', DS4IdentityBlock),
        ('sig_identity', ctypes.c_uint8 * 0x100),
    )


class DS4FullKeyBlock(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('identity', DS4IdentityBlock),
        ('sig_identity', ctypes.c_uint8 * 0x100),
        ('private_key', DS4PrivateKeyBlock),
    )


class DS4Response(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('sig', ctypes.c_uint8 * 0x100),
        ('signed_identity', DS4SignedIdentityBlock),
    )


AUTH_REQ_SIZE = 0x100
AUTH_RESP_SIZE = 0x410


class DS4Key:
    def __init__(self, ds4key_file: io.FileIO):
        ds4key = DS4FullKeyBlock()
        actual = ds4key_file.readinto(ds4key)
        if actual != ctypes.sizeof(DS4FullKeyBlock):
            raise ValueError('DS4Key too small.')

        n = bytes_to_long(bytes(ds4key.identity.modulus))
        e = bytes_to_long(bytes(ds4key.identity.exponent))
        p = bytes_to_long(bytes(ds4key.private_key.p))
        q = bytes_to_long(bytes(ds4key.private_key.q))
        dp1 = bytes_to_long(bytes(ds4key.private_key.dp1))
        dq1 = bytes_to_long(bytes(ds4key.private_key.dq1))
        pq = bytes_to_long(bytes(ds4key.private_key.pq))

        d = Integer(e).inverse((p-1) * (q-1))
        pq_from_pq = Integer(q).inverse(p)
        dp1_from_pq = Integer(d) % (p-1)
        dq1_from_pq = Integer(d) % (q-1)
        if Integer(pq) != pq_from_pq or Integer(dp1) != dp1_from_pq or Integer(dq1) != dq1_from_pq:
            raise ValueError('Bad key block (CRT factors inconsistent with P and Q)')

        key = RSA.construct((n, e, d, p, q), consistency_check=True)
        fppub = SHA256.new(key.publickey().exportKey('DER')).hexdigest()
        fppriv = SHA256.new(key.exportKey('DER')).hexdigest()

        self._key = key
        self._pss = pss.new(self._key)
        self._ds4id = DS4SignedIdentityBlock()
        self._ds4id.identity = ds4key.identity
        self._ds4id.sig_identity = ds4key.sig_identity

        logger.info('DS4Key loaded fingerprint=%s, private_fingerprint=%s', fppub, fppriv)

    def sign_challenge(self, challenge: bytes):
        sha = SHA256.new(challenge)
        sig = self._pss.sign(sha)

        buf = DS4Response()
        ctypes.memmove(buf.sig, sig, DS4Response.sig.size)
        buf.signed_identity = self._ds4id
        return buf


class DS4StateTracker:
    def __init__(self, ds4key: DS4Key, features: FeatureConfiguration):
        # Initialize report A
        self._input_report_bufa = bytearray(InputReport())
        logger.debug('Buffer A: %s', hex(id(self._input_report_bufa)))
        self._input_report_a = InputReport.from_buffer(self._input_report_bufa)

        # Copy report A to report B
        self._input_report_bufb = bytearray(InputReport())
        logger.debug('Buffer B: %s', hex(id(self._input_report_bufb)))
        self._input_report_b = InputReport.from_buffer(self._input_report_bufb)

        # Set current sending and next report references
        self.input_report = self._input_report_a
        self._input_report_next = self._input_report_b
        self.input_report_buf = self._input_report_bufa
        self._input_report_next_buf = self._input_report_bufb

        # Create input report lock
        self.input_report_lock = threading.Lock()

        # Create dummy feedback report
        self.feedback_report = FeedbackReport()

        # Initiallize auth state tracker
        self._ds4key = ds4key
        self._nonce = io.BytesIO()
        self._response = io.BytesIO()
        self._auth_status = 0x10
        self._auth_seq = 0
        self._auth_req_page = 0
        self._auth_resp_page = 0
        self._auth_req_size = AuthReport.data.size
        self._auth_resp_size = AuthReport.data.size
        self._auth_req_max_page = -(-AUTH_REQ_SIZE // self._auth_req_size) - 1
        self._auth_resp_max_page = -(-AUTH_RESP_SIZE // self._auth_req_size) - 1
        self._auth_rsa_task = futures.ThreadPoolExecutor()

        # Initialize feature configuration
        self._features = features

    @property
    def auth_req_size(self):
        return self._auth_req_size

    @auth_req_size.setter
    def auth_req_size(self, val: int):
        if val > AuthReport.data.size:
            raise ValueError('Data size too big')
        self._auth_req_size = val
        self._auth_req_max_page = -(-AUTH_REQ_SIZE // val) - 1

    @property
    def auth_resp_size(self):
        return self._auth_resp_size

    @auth_resp_size.setter
    def auth_resp_size(self, val):
        if val > AuthReport.data.size:
            raise ValueError('Data size too big')
        self._auth_resp_size = val
        self._auth_resp_max_page = -(-AUTH_RESP_SIZE // val) - 1

    def auth_reset(self):
        self._auth_status = 0x10
        self._auth_req_page = 0
        self._auth_resp_page = 0
        self._nonce.seek(0)
        self._response.seek(0)
        self._nonce.truncate(0)
        self._response.truncate(0)

    def swap_buffer(self):
        with self.input_report_lock:
            self.swap_buffer_nolock()

    def swap_buffer_nolock(self):
        self.input_report, self._input_report_next = self._input_report_next, self.input_report
        self.input_report_buf, self._input_report_next_buf = self._input_report_next_buf, self.input_report_buf

    def sync_buffer(self):
        with self.input_report_lock:
            self.sync_buffer_nolock()

    def sync_buffer_nolock(self):
        #ctypes.memmove(self._input_report_next, self.input_report, ctypes.sizeof(InputReport))
        ctypes.pointer(self._input_report_next)[0] = self.input_report

    @contextlib.contextmanager
    def start_modify_report(self) -> Iterator[InputReport]:
        with self.input_report_lock:
            yield self._input_report_next

    def process_feedback(self, data: memoryview):
        if len(data) != ctypes.sizeof(FeedbackReport):
            logger.error('Wrong size for feedback report. Ignored')
            return
        self.feedback_report = FeedbackReport.from_buffer_copy(data)

    def get_feature_configuration(self, ep0: io.FileIO):
        ep0.write(self._features)

    def prepare_challenge(self):
        try:
            self._response.write(self._ds4key.sign_challenge(self._nonce.getvalue()))
            self._response.seek(0)
        except Exception:
            logger.exception('Challenge signing failed with an exception.')
            # TODO
            self._auth_status = 0xff
        else:
            self._auth_status = 0x0

    def get_page_size(self, ep0: io.FileIO):
        buf = AuthPageSizeReport(type=ReportType.get_auth_page_size)
        buf.size_challenge = self.auth_req_size
        buf.size_response = self.auth_resp_size
        ep0.write(buf)

    def set_challenge(self, ep0: io.FileIO):
        buf = AuthReport()
        ep0.readinto(buf)
        if buf.type != int(ReportType.set_challenge):
            raise TypeError('Invalid request type for request set_challenge.')
        if buf.page != 0 and buf.seq != self._auth_seq:
            logger.warning("Inconsistent sequence value.")
        elif buf.page != self._auth_req_page:
            logger.warning("Out of order challenge write.")
        self._auth_seq = buf.seq
        valid_data_size = min(max(0, AUTH_REQ_SIZE - buf.page * self._auth_req_size), self._auth_req_size)
        self._nonce.write(memoryview(buf.data)[:valid_data_size])
        if self._auth_req_page == self._auth_req_max_page:
            self._auth_status = 0x01
            self._auth_rsa_task.submit(self.prepare_challenge)
        self._auth_req_page += 1

    def get_auth_status(self, ep0: io.FileIO):
        buf = AuthStatusReport(type=ReportType.get_auth_status)
        buf.seq = self._auth_seq
        buf.status = self._auth_status
        ep0.write(buf)

    def get_response(self, ep0: io.FileIO):
        buf = AuthReport(type=ReportType.get_response)
        buf.seq = self._auth_seq
        buf.page = self._auth_resp_page
        if self._response.readinto(buf.data) == 0:
            logger.warning('Attempt to read outside of the auth response buffer.')
        if self._auth_resp_page == self._auth_resp_max_page:
            self.auth_reset()
        ep0.write(buf)
        if self._auth_status == 0x0:
            self._auth_resp_page += 1


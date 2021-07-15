import base64
import io
import unittest
import os
import zlib
import time
from ffsds4 import ds4, sequencer

from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256

JEDI_TEST_CA = '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzps0083KBRnwO4AA0PBI
hoch62Y5RG4lg8IrwgjoZgL/xDarQlxnJLT8dYTB+iAq+EIVSZcZmLFrOyCJguDU
A6PJoGoHGuboGT4SlJtq1Injb8IZT5X+pI2jkCJgMpE3HYX51aD4p2uxtY7pssXr
l4h/ztMhk0zeV8LV093W/73TDQp6J0Uao6K3x17GZ0bBILu4rO+T4iTBEbgEB8xi
JJcORgsOMSlRntH6dWzjnWcokoT1y1nnjU8xKdtccD8wPEyKqnpi82kah5nCdFEE
SNej4ycVKw3D/qprLJFsgU8d0WL4cbKwe37OibRsiXe55AUejWTdcIslFySGMKMz
YwIDAQAB
-----END PUBLIC KEY-----
'''.strip()

TEST_DS4KEY = '''
AAAAAAAAAAAAAQAB3q2+765x6hsXUzjr8YywrxxLJfPx33VIIOVsm4RuTPj7GBnfBAb6+79gIHuP
D2tJXZAzIPVdf0zIfpP3UTU+aj+6sos7v6xVNmaLexQGPTlSNu1dCvx38q6OqUbefT8eSejEk+Tg
oaePdrn+51Ho2kThNODbF68QJ2VzBU/QEK6MKJa8cgXWeFp1tMM+T4CuBO+Ia1Fxh2rZtE562Jyv
9VzGWlpjt5hAS30x5bNdiGsc69OGbGx2mPGxA0l7SA4sEbMpgUusQ9wJIrGKgPvBf6vYHU/hecou
RFLMZdypsmbWXk4p2053k00Ndsf1MxxBZO+nqi6I9oXp9MmkPKPYNZhHQ7cAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAQABDLtMvIm9B5qYYvBI6dnuwMqdyDWQpf7W67hGVB6BRx6xhWZIh0xWiXpB
gIzYZga/WnMwqU4Os7ZqgAU+BXkip6gmulGXouoGGY0iHam1K9v8hNVaxIDUGEa+WmQQ4Z/CJqRW
1irFh1g9ohQBGquiYHEQvU5WlZGwfYd2jxnmsAm+WUW3zC28TzgMmmN4gj2GrQ25YLlx15Nh9afi
vU1DbDXFKh7S681CkS3dn7Sfmm+7/EEu7F4cThu3PA+hddrpg6AF1kOoHtNahAaX6PgUnqigqJGW
bdwl3Df9oPB+xDHiSMZq2amEI/sKPHac/cNIXmeLDpi8Ef4deYrO4hZkd74rrjsujbyROOefuAFd
Qo8AGkJ3ZRV6V7J8fDtu/UcmA7QPS/UU3hngp7jX8fKONNgNnsZ1s4nPuPvs/w5bS9WJZnBln7zC
SwG9RB0GaTcnhkRzjsSyXNmXjIoBWF6m9Xbn/ytJ7Y0X18o4Dyqhe5jFHNk419Cvw+QyWcV0+4Yj
6tStN3NHbzpwkeGs1eM4Jb4Y9GwZuVHZ5qHP9P7zupTzUQYn+6M+TtWuK2wMWxWATMZtL8FgQg+d
MGFf2BWPBDbcoPedeJmkPiG90GIpXbkcoGCoc/pBjFKEe8cLgDDYawVWbKOp526ENzPkahyl1Z6O
qqnBGGHF4dCZ3ehYY10xvc8m37hnGD0gKKDCipg8OzSjKgOgqI2DvBfqm89X6tORJ2cgxcKKVj7I
lINOhG/CC136XxME+vZRvt2/7ZVaV0QaJhqwDsn7vHuyc9jVelseUHOJc3Xh3EgAWPW6XEVcQrZ1
pjKicxgYZq1g4zgm73fqQXoBtdexOpJMmZqorabFmaqqrQ26NB32ZreT4dk0Eybq6q3pClY3jqfQ
tKlKhS6Cr7yPJ333VPUzi+bX80ETHpHuxHzF9/1W+ilMzj/Q8olCsUvn2XPipJosTHJqN4FSg++x
yAFuzPXW2z0T82614LXQ2aYpn65QpSQS6lc2ft2HJ0I4lb8UVWH6U2NlOAr3skgpNQGn/LSmLoLu
xfMLH9sz8JS+y5XbGNeb3oVIymFLAzm5HO9hqnZf+nIEwbglUGwB6XdC9pRoN6m+XeTdRaKavB+Q
MweJLgztMiQav/NXKzL96FZ8svv/05H/FNpZ1ktuR2beae4n5/Evy9Gbx8ej0mlsgVa6jQrVnYc=
'''.strip()

TEST_DS4KEY_JUST_KEY = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArnHqGxdTOOvxjLCvHEsl8/HfdUgg5WybhG5M+PsYGd8EBvr7
v2Age48Pa0ldkDMg9V1/TMh+k/dRNT5qP7qyizu/rFU2Zot7FAY9OVI27V0K/Hfy
ro6pRt59Px5J6MST5OChp492uf7nUejaROE04NsXrxAnZXMFT9AQrowolrxyBdZ4
WnW0wz5PgK4E74hrUXGHatm0TnrYnK/1XMZaWmO3mEBLfTHls12Iaxzr04ZsbHaY
8bEDSXtIDiwRsymBS6xD3AkisYqA+8F/q9gdT+F5yi5EUsxl3KmyZtZeTinbTneT
TQ12x/UzHEFk76eqLoj2hen0yaQ8o9g1mEdDtwIDAQABAoIBABOEIxDM1z6zBt8a
lTyxG5njIYDZhPSl5fA29t2UGeorDSRKyAdtFbU9GBiEqLcNQU6yGx/X/nFHZgpy
5SgkFv2Evbjl/6QRTr+6wva6v/JmSmhccwYcZ8vJ8HEzTkmAVJtyliNM5ZeBcRe0
2VaDa4sMd+XaBM5Qw/Nd77/XZmMWmo7GaKlzLF+mgxqAcV/4RMjMW+4IuUyOLVBS
kSG3NKcBXidL/Yu3D7ivNio6PrBS1ZOzumjuVdjGNgiLR5+vdQcfycptviuppus0
c4SbLtxjP/8UmHULCGt3sTg4zxHK0GeRibHwXehA31I+ImCoB+B2TfD/jDQYodT2
PXXi6+ECgYEAviuuOy6NvJE455+4AV1CjwAaQndlFXpXsnx8O279RyYDtA9L9RTe
GeCnuNfx8o402A2exnWzic+4++z/DltL1YlmcGWfvMJLAb1EHQZpNyeGRHOOxLJc
2ZeMigFYXqb1duf/K0ntjRfXyjgPKqF7mMUc2TjX0K/D5DJZxXT7hiMCgYEA6tSt
N3NHbzpwkeGs1eM4Jb4Y9GwZuVHZ5qHP9P7zupTzUQYn+6M+TtWuK2wMWxWATMZt
L8FgQg+dMGFf2BWPBDbcoPedeJmkPiG90GIpXbkcoGCoc/pBjFKEe8cLgDDYawVW
bKOp526ENzPkahyl1Z6OqqnBGGHF4dCZ3ehYY10CgYAxvc8m37hnGD0gKKDCipg8
OzSjKgOgqI2DvBfqm89X6tORJ2cgxcKKVj7IlINOhG/CC136XxME+vZRvt2/7ZVa
V0QaJhqwDsn7vHuyc9jVelseUHOJc3Xh3EgAWPW6XEVcQrZ1pjKicxgYZq1g4zgm
73fqQXoBtdexOpJMmZqorQKBgQCmxZmqqq0NujQd9ma3k+HZNBMm6uqt6QpWN46n
0LSpSoUugq+8jyd991T1M4vm1/NBEx6R7sR8xff9VvopTM4/0PKJQrFL59lz4qSa
LExyajeBUoPvscgBbsz11ts9E/NuteC10NmmKZ+uUKUkEupXNn7dhydCOJW/FFVh
+lNjZQKBgDgK97JIKTUBp/y0pi6C7sXzCx/bM/CUvsuV2xjXm96FSMphSwM5uRzv
Yap2X/pyBMG4JVBsAel3QvaUaDepvl3k3UWimrwfkDMHiS4M7TIkGr/zVysy/ehW
fLL7/9OR/xTaWdZLbkdm3mnuJ+fxL8vRm8fHo9JpbIFWuo0K1Z2H
-----END RSA PRIVATE KEY-----
'''.strip()

INITIAL_DS4_INPUT_REPORT = bytes.fromhex('''
01
80 80 80 80
080000
00 00
0000
ff
0000 0000 0000
0000 0000 0000
0000000000
08
0000
00
00 80000000 80000000
00 80000000 80000000
00 80000000 80000000
000000
''')

FEATURE_CONFIG_ALL_ENABLED = bytes.fromhex('''
03
2127
04
4f
00
2c 56
a00f 3d00 e803
0100 0020
0d0d
00000000
00 00 00
000000000000000000000000000000000000000000
''')

# TODO: Touchpad packet sequences start from 1 but it shouldn't really matter as long as they are incrementing at the right time...
TP_SET_ONE_INVALIDATED = bytes.fromhex('''
01
02 8064800c 81c8c012
00 80000000 80000000
00 80000000 80000000
''')

TP_SET_ONE = bytes.fromhex('''
01
01 0064800c 01c8c012
00 80000000 80000000
00 80000000 80000000
''')

TP_SET_MULTI = bytes.fromhex('''
02
01 0064800c 01c8c012
02 0096800c 01fac012
00 80000000 80000000
''')

TP_SET_ONE_AFTER_RELEASE = bytes.fromhex('''
01
03 0264800c 03c8c012
00 80000000 80000000
00 80000000 80000000
''')


class DS4Test(unittest.TestCase):
    def test_ds4key_load(self):
        '''
        DS4Key loading.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        _ds4key = ds4.DS4Key(ds4key_io)

    def test_ds4key_sign(self):
        '''
        Challenge signing with DS4Key object directly.
        '''
        ds4key_bytes = base64.b64decode(TEST_DS4KEY)
        ds4key_io = io.BytesIO(ds4key_bytes)
        ds4id_expected = ds4key_bytes[:0x310]

        ds4key = ds4.DS4Key(ds4key_io)

        challenge = os.urandom(256)
        response = ds4key.sign_challenge(challenge)

        resp_bytes = bytes(response)
        sig = resp_bytes[:0x100]
        ds4id = resp_bytes[0x100:]

        self.assertEqual(ds4id.hex(), ds4id_expected.hex(), 'DS4ID mismatch.')
        ds4key_key = RSA.import_key(TEST_DS4KEY_JUST_KEY)
        ds4key_pss = pss.new(ds4key_key)
        sha = SHA256.new(challenge)
        try:
            ds4key_pss.verify(sha, sig)
        except ValueError as e:
            self.fail(f'Response verification failed. ({str(e)})')

    def test_tracker_auth_full(self):
        '''
        Authentication with state tracker (API-level DS4 protocol mockup).
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        ds4id_expected = ds4key_io.getvalue()[:0x310]
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        challenge = io.BytesIO(b'\x00' * 256)
        page = 0
        tracker.auth.reset()
        while challenge.tell() < 256:
            data = bytearray(56)
            challenge.readinto(data)
            packet = b'\xf0\x01' + page.to_bytes(1, 'big') + b'\x00' + bytes(data)
            crc = zlib.crc32(packet)
            packet += crc.to_bytes(4, 'little')
            assert len(packet) == 64, 'Test case bug: invalid challenge packet length.'
            packet_io = io.BytesIO(packet)
            tracker.auth.set_challenge(packet_io)
            page += 1
        wait_count = 0
        while True:
            response_io = io.BytesIO()
            tracker.auth.get_status(response_io)
            response = response_io.getvalue()
            self.assertEqual(len(response), 16, 'Wrong GetAuthStatus length.')
            self.assertEqual(response[0], 0xf2, 'Invalid GetAuthStatus magic.')
            self.assertEqual(response[1], 0x1, 'Wrong GetAuthStatus sequence counter.')
            self.assertIn(response[2], (0x01, 0x00), 'Invalid auth status.')
            if response[2] == 0x01:
                wait_count += 1
                time.sleep(0.05)
                if wait_count > 100:
                    self.fail('Auth took too long to respond.')
            elif response[2] == 0x00:
                break
        remaining = 0x410
        page = 0
        response_io_full = io.BytesIO()
        while remaining > 0:
            response_io = io.BytesIO()
            tracker.auth.get_response(response_io)
            response = response_io.getvalue()
            self.assertEqual(len(response), 64, 'Wrong GetResponse length.')
            self.assertEqual(response[0], 0xf1, 'Invalid GetResponse magic.')
            self.assertEqual(response[1], 0x1, 'Wrong GetResponse sequence counter.')
            self.assertEqual(response[2], page, 'Wrong GetResponse page counter.')
            data = response[4:4+min(56, remaining)]
            response_io_full.write(data)  
            remaining = max(0, remaining - 56)
            page += 1
        response_full = response_io_full.getvalue()
        assert len(response_full) == 0x410, 'Test case bug: wrong full response length.'
        sig = response_full[:0x100]
        ds4id = response_full[0x100:]

        self.assertEqual(ds4id.hex(), ds4id_expected.hex(), 'DS4ID mismatch.')
        ds4key_key = RSA.import_key(TEST_DS4KEY_JUST_KEY)
        ds4key_pss = pss.new(ds4key_key)
        sha = SHA256.new(challenge.getvalue())
        try:
            ds4key_pss.verify(sha, sig)
        except ValueError as e:
            self.fail(f'Response verification failed. ({str(e)})')

    # TODO DS4 API

    def test_input_init(self):
        '''
        Initialize input report.
        '''
        report = ds4.InputReport()
        self.assertEqual(bytes(report).hex(), INITIAL_DS4_INPUT_REPORT.hex())

    def test_input_set_dpad(self):
        '''
        Set DPad.
        '''
        report = ds4.InputReport()
        report.set_dpad(ds4.DPadPosition.nw)
        actual = bytes(report)[5] & 0xf
        expected = 0x7
        self.assertEqual(actual, expected)

    def test_input_set_button(self):
        '''
        Set buttons.
        '''
        report = ds4.InputReport()
        report.set_dpad(ds4.DPadPosition.s)
        report.set_button(ds4.ButtonType.l3, True)
        report.set_button(ds4.ButtonType.r1, True)
        report.set_button(ds4.ButtonType.ps, True)
        report.set_button(ds4.ButtonType.circle, True)
        report.set_button(ds4.ButtonType.triangle, True)
        actual = bytes(report)[5:8].hex()
        expected = 'c44201'
        self.assertEqual(actual, expected)

    def test_input_clear_button(self):
        '''
        Clear buttons.
        '''
        report = ds4.InputReport()
        report.set_dpad(ds4.DPadPosition.s)
        report.set_button(ds4.ButtonType.l3, True)
        report.set_button(ds4.ButtonType.r1, True)
        report.set_button(ds4.ButtonType.ps, True)
        report.set_button(ds4.ButtonType.circle, True)
        report.set_button(ds4.ButtonType.triangle, True)
        report.clear_buttons()
        actual = bytes(report)[5:8].hex()
        # dpad should stay south
        expected = 'c00000'
        self.assertEqual(actual, expected)

    def test_input_touchpad_one(self):
        '''
        One frame 2 point touch.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.touch.queue_touchpad((100, 200), (200, 300))

        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[33:61].hex()
        expected = TP_SET_ONE.hex()
        self.assertEqual(actual, expected)

    def test_input_touchpad_multiple(self):
        '''
        Two frames with moving 2 point touch.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.touch.queue_touchpad((100, 200), (200, 300))
        tracker.touch.queue_touchpad((150, 200), (250, 300))

        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[33:61].hex()
        expected = TP_SET_MULTI.hex()
        self.assertEqual(actual, expected)

    def test_input_touchpad_release_one(self):
        '''
        Release one point only will only result in that point being
        invalidated. Only checks the invalidation states.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.touch.queue_touchpad((100, 200), (200, 300))
        tracker.prepare_for_report_submission()
        tracker.touch.queue_touchpad(release_pos0=False)

        report = tracker.prepare_for_report_submission()
        tp_report = bytes(report)[33:61]

        actual = (bool(tp_report[2] & 0x80), bool(tp_report[6] & 0x80))
        expected = (False, True)
        self.assertEqual(actual, expected)

    def test_input_touchpad_release_both(self):
        '''
        Release both points will cause both points to be invalidated. Only
        checks the invalidation states.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.touch.queue_touchpad((100, 200), (200, 300))
        tracker.prepare_for_report_submission()
        tracker.touch.queue_touchpad()

        report = tracker.prepare_for_report_submission()
        tp_report = bytes(report)[33:61]

        actual = (bool(tp_report[2] & 0x80), bool(tp_report[6] & 0x80))
        expected = (True, True)
        self.assertEqual(actual, expected)

    def test_input_touchpad_hold(self):
        '''
        Not updating the points will cause them to be held at position with
        frame seq incrementing.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.touch.queue_touchpad((100, 200), (200, 300))
        # Hold for 2 frames
        tracker.prepare_for_report_submission()
        tracker.prepare_for_report_submission()

        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[33:61].hex()
        expected_bytes = bytearray(TP_SET_ONE)
        # Frame sequence should be 3 now
        expected_bytes[1] = 3
        expected = expected_bytes.hex()
        self.assertEqual(actual, expected)

    def test_input_touchpad_nohold(self):
        '''
        Touch shouldn't be held when there are actual new points.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.touch.queue_touchpad((230, 125), (500, 100))
        tracker.prepare_for_report_submission()
        tracker.touch.queue_touchpad((100, 200), (200, 300))

        report = tracker.prepare_for_report_submission() # this should do nothing to the touchpad frames now
        actual = bytes(report)[33:61].hex()
        expected_bytes = bytearray(TP_SET_ONE)
        # Frame sequence should be 2 now
        expected_bytes[1] = 2
        expected = expected_bytes.hex()
        # Exactly as before with empty unused frames
        self.assertEqual(actual, expected)

    def test_input_touchpad_nohold_after_release(self):
        '''
        Touch shouldn't be held when they are released. Instead they should be invalidated.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.touch.queue_touchpad((100, 200), (200, 300))
        tracker.prepare_for_report_submission()
        tracker.touch.queue_touchpad()

        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[33:61].hex()
        expected = TP_SET_ONE_INVALIDATED.hex()
        self.assertEqual(actual, expected)

    def test_input_touchpad_nohold_after_release_2(self):
        '''
        Invalidated touches will continue to be available despite invalidated.

        This mimics official DS4 behavior.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        # Initial frame
        tracker.touch.queue_touchpad((100, 200), (200, 300))
        tracker.prepare_for_report_submission()
        # Release - This is one packet despite all points are invalidated.
        tracker.touch.queue_touchpad()
        tracker.prepare_for_report_submission()
        # Sustain the invalidated packet. No value should be incrementing.
        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[33:61].hex()
        expected = TP_SET_ONE_INVALIDATED.hex()
        self.assertEqual(actual, expected)

    def test_input_touchpad_touch_seq_inc(self):
        '''
        Touch sequence should be increased when different touches are
        registered.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        # Initial frame
        tracker.touch.queue_touchpad((100, 200), (200, 300))
        tracker.prepare_for_report_submission()
        # Release - This is one packet despite all points are invalidated.
        tracker.touch.queue_touchpad()
        tracker.prepare_for_report_submission()
        # Second frame with 2 different points
        tracker.touch.queue_touchpad((100, 200), (200, 300))

        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[33:61].hex()
        expected = TP_SET_ONE_AFTER_RELEASE.hex()
        self.assertEqual(actual, expected)

    def test_tracker_edit_context(self):
        '''
        Report editing context and buffer swapping.
        '''
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)
        with tracker.start_modify_report() as report:
            report: ds4.InputReport
            report.set_button(ds4.ButtonType.ps, True)
        with tracker.input_report_lock:
            tracker.swap_buffer_nolock()
            tracker.sync_buffer_nolock()
        actual = tracker.input_report_submitting_buf[5:8].hex()
        actual_next = tracker.input_report_submitting_buf[5:8].hex()
        expected = '080001'
        self.assertEqual(actual, expected)
        self.assertEqual(actual_next, expected)

    def test_imu_set_angular_velocity(self):
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.imu.set_angular_velocity(90, 90, 90)

        report = tracker.prepare_for_report_submission()

        actual = bytes(report)[13:25].hex()
        # 1000 * 90(deg) / 61 = approx. 1475
        # (1475, 1475, 1475), (0, 0, 0)
        expected = 'c305c305c305000000000000'
        self.assertEqual(actual, expected)

    def test_imu_set_linear_acceleration(self):
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        tracker.imu.set_linear_acceleration(1, 1, 1)

        report = tracker.prepare_for_report_submission()

        actual = bytes(report)[13:25].hex()
        # (0, 0, 0), (8192, 8192, 8192)
        expected = '000000000000002000200020'
        self.assertEqual(actual, expected)

    def test_imu_set_attitude_position(self):
        current_time = 0
        _mock_time_func = lambda: current_time

        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features, imu_time_func=_mock_time_func)
        # Put into attitude-position mode
        tracker.imu.use_attitude_position = True

        # (30, 30, 30), (0, 0, 0) @ 50ms
        current_time = 0.05
        tracker.imu.set_attitude_position(current_time, 30, 30, 30, 0, 0, 0)
        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[13:25].hex()
        expected = '6c266c266c26000000000000'
        self.assertEqual(actual, expected)

        # (45, 45, 45), (3, 4, 5) @ 100ms
        current_time = 0.10
        tracker.imu.set_attitude_position(current_time, 45, 45, 45, 3, 4, 5)
        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[13:25].hex()
        expected = '361336133613eb0339058806'
        self.assertEqual(actual, expected)

        # (60, 50, 10), (6, 10, 5) @ 150ms
        current_time = 0.15
        tracker.imu.set_attitude_position(current_time, 60, 50, 10, x=6, y=10)
        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[13:25].hex()
        expected = '361367062dd3eb03d6070000'
        self.assertEqual(actual, expected)

    def test_imu_sustain(self):
        current_time = 0
        _mock_time_func = lambda: current_time

        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features, imu_time_func=_mock_time_func)
        # Put into attitude-position mode
        tracker.imu.use_attitude_position = True

        # (30, 30, 30), (0, 0, 0) @ 50ms
        current_time = 0.05
        tracker.imu.set_attitude_position(current_time, 30, 30, 30, 0, 0, 0)
        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[13:25].hex()
        expected = '6c266c266c26000000000000'
        self.assertEqual(actual, expected)

        # Sustain @ 100ms
        current_time = 0.10
        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[13:25].hex()
        expected = '000000000000000000000000'
        self.assertEqual(actual, expected)

        # (45, 45, 45), (3, 4, 5) @ 150ms
        current_time = 0.15
        tracker.imu.set_attitude_position(current_time, 45, 45, 45, 3, 4, 5)
        report = tracker.prepare_for_report_submission()
        actual = bytes(report)[13:25].hex()
        expected = '361336133613eb0339058806'
        self.assertEqual(actual, expected)

    def test_feature_config_all_enabled(self):
        '''
        Feature config - All enabled.
        '''
        features = ds4.FeatureConfiguration(
            enable_touchpad=True,
            enable_imu=True,
            enable_led=True,
            enable_rumble=True,
        )
        actual = bytes(features).hex()
        self.assertEqual(actual, FEATURE_CONFIG_ALL_ENABLED.hex())

    def test_sequencer_lineartween(self):
        tw = sequencer.LinearTween(0, 5.0, (0, 5))
        self.assertFalse(tw.done)
        self.assertAlmostEqual(tw.at(1.0), 1.0)
        self.assertAlmostEqual(tw.at(1.5), 1.5)
        self.assertAlmostEqual(tw.at(2.0), 2.0)
        self.assertAlmostEqual(tw.at(3.5), 3.5)
        self.assertAlmostEqual(tw.at(5.0), 5.0)
        self.assertTrue(tw.done)

    def test_sequencer_polyeasetween_quad(self):
        tw = sequencer.PolyEaseTween(0, 1, (0, 1))
        self.assertFalse(tw.done)
        self.assertAlmostEqual(tw.at(0.1), 0.02)
        self.assertAlmostEqual(tw.at(0.35), 0.245)
        self.assertAlmostEqual(tw.at(0.5), 0.5)
        self.assertAlmostEqual(tw.at(0.62), 0.7112)
        self.assertAlmostEqual(tw.at(0.77), 0.8942)
        self.assertAlmostEqual(tw.at(0.9), 0.98)
        self.assertAlmostEqual(tw.at(1.0), 1.0)
        self.assertTrue(tw.done)

    def test_sequencer_polyeasetween_cubic(self):
        tw = sequencer.PolyEaseTween(0, 1, (0, 1), exp=3)
        self.assertFalse(tw.done)
        self.assertAlmostEqual(tw.at(0.1), 0.004)
        self.assertAlmostEqual(tw.at(0.24), 0.055296)
        self.assertAlmostEqual(tw.at(0.42), 0.296352)
        self.assertAlmostEqual(tw.at(0.5), 0.5)
        self.assertAlmostEqual(tw.at(0.71), 0.902444)
        self.assertAlmostEqual(tw.at(0.87), 0.991212)
        self.assertAlmostEqual(tw.at(0.9), 0.996)
        self.assertAlmostEqual(tw.at(1.0), 1.0)
        self.assertTrue(tw.done)

if __name__ == '__main__':
    unittest.main()

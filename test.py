import base64
import io
import unittest
import os
import zlib
import time
from ffsds4 import ds4

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
00
0000 0000 0000
0000 0000 0000
00000000
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

class DS4Test(unittest.TestCase):
    def test_ds4key_load(self):
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        _ds4key = ds4.DS4Key(ds4key_io)

    def test_ds4key_sign(self):
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
        ds4key_io = io.BytesIO(base64.b64decode(TEST_DS4KEY))
        ds4key = ds4.DS4Key(ds4key_io)
        ds4id_expected = ds4key_io.getvalue()[:0x310]
        features = ds4.FeatureConfiguration()
        tracker = ds4.DS4StateTracker(ds4key, features)

        challenge = io.BytesIO(b'\x00' * 256)
        page = 0
        tracker.auth_reset()
        while challenge.tell() < 256:
            data = bytearray(56)
            challenge.readinto(data)
            packet = b'\xf0\x01' + page.to_bytes(1, 'big') + b'\x00' + bytes(data)
            crc = zlib.crc32(packet)
            packet += crc.to_bytes(4, 'little')
            assert len(packet) == 64, 'Test case bug: invalid challenge packet length.'
            packet_io = io.BytesIO(packet)
            tracker.set_challenge(packet_io)
            page += 1
        wait_count = 0
        while True:
            response_io = io.BytesIO()
            tracker.get_auth_status(response_io)
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
            tracker.get_response(response_io)
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
        report = ds4.InputReport()
        self.assertEqual(bytes(report).hex(), INITIAL_DS4_INPUT_REPORT.hex())

    def test_input_set_dpad(self):
        report = ds4.InputReport()
        report.set_dpad(ds4.DPadPosition.nw)
        actual = bytes(report)[5] & 0xf
        expected = 0x7
        self.assertEqual(actual, expected)

    def test_input_set_button(self):
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

    def test_tracker_edit_context(self):
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
        actual = tracker.input_report_buf[5:8].hex()
        actual_next = tracker.input_report_buf[5:8].hex()
        expected = '080001'
        self.assertEqual(actual, expected)
        self.assertEqual(actual_next, expected)

    def test_feature_config_all_enabled(self):
        features = ds4.FeatureConfiguration(
            enable_touchpad=True,
            enable_imu=True,
            enable_led=True,
            enable_rumble=True,
        )
        actual = bytes(features).hex()
        self.assertEqual(actual, FEATURE_CONFIG_ALL_ENABLED.hex())

if __name__ == '__main__':
    unittest.main()

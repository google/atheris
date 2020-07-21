# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for FuzzedDataProvider pybind."""

import math
import random
import sys

import atheris

from google3.testing.pybase import googletest

if sys.version_info[0] >= 3:
  codepoint = chr

  def to_bytes(n, length):
    return n.to_bytes(length, "little")

else:
  # functionality from python3's chr() function is called unichr() in python2
  codepoint = unichr

  # functionality from python3's int.to_bytes()
  def to_bytes(n, length):
    h = "%x" % n
    s = ("0" * (len(h) % 2) + h).zfill(length * 2).decode("hex")
    return s[::-1]


ASCII_BYTEMARK = to_bytes(1, length=1)
UTF16_BYTEMARK = to_bytes(2, length=1)
UTF32_BYTEMARK = to_bytes(0, length=1)

HIGH_SURROGATE = to_bytes(0xDAA1, length=2)
LOW_SURROGATE = to_bytes(0xDD03, length=2)
BYTE_ORDER_BIG_ENDIAN = to_bytes(0xFEFF, length=2)
BYTE_ORDER_LITTLE_ENDIAN = to_bytes(0xFEFF, length=2)


class FuzzedDataProviderTest(googletest.TestCase):

  def testUnicodeActuallyAscii(self):
    fdp = atheris.FuzzedDataProvider(ASCII_BYTEMARK + b"abc123\0\x7f" +
                                     BYTE_ORDER_LITTLE_ENDIAN + b"\xd1")
    expected = "abc123\0\x7f\x7f\x7e\x51"
    actual = fdp.ConsumeUnicode(atheris.ALL_REMAINING)
    self.assertEqual(expected, actual)

  def testUnicode16(self):
    fdp = atheris.FuzzedDataProvider(UTF16_BYTEMARK + b"abc123\0\x7f" +
                                     HIGH_SURROGATE + LOW_SURROGATE + b"\xd1")

    expected = str()
    expected += b"abc123\0\x7f".decode("utf-16")
    expected += codepoint(0xDAA1) + codepoint(0xDD03)

    actual = fdp.ConsumeUnicode(atheris.ALL_REMAINING)
    self.assertEqual(expected, actual)

  def testUnicode16NoSurrogate(self):
    fdp = atheris.FuzzedDataProvider(UTF16_BYTEMARK + b"abc123\0\x7f" +
                                     HIGH_SURROGATE + LOW_SURROGATE + b"\xd1")

    high_surrogate_sub = to_bytes(0xDAA1 - 0xd800, length=2)
    low_surrogate_sub = to_bytes(0xDD03 - 0xd800, length=2)

    expected = str()
    expected += (b"abc123\0\x7f" + high_surrogate_sub +
                 low_surrogate_sub).decode("utf-16")

    actual = fdp.ConsumeUnicodeNoSurrogates(atheris.ALL_REMAINING)
    self.assertEqual(expected, actual)

  def testUnicode32(self):
    fdp = atheris.FuzzedDataProvider(UTF32_BYTEMARK + b"dc\x0e\0" + b"4321" +
                                     HIGH_SURROGATE + b"\0\0" + LOW_SURROGATE +
                                     b"\0\0" + b"\xd1")

    chunk1 = b"dc\x0e\0".decode("utf-32")
    chunk2 = codepoint(0x31323334 & 0x10ffff)
    chunk3 = codepoint(0xDAA1)
    chunk4 = codepoint(0xDD03)

    expected = (chunk1 + chunk2 + chunk3 + chunk4)

    actual = fdp.ConsumeUnicode(atheris.ALL_REMAINING)
    for i in range(len(actual)):
      self.assertEqual(ord(expected[i]), ord(actual[i]))
    self.assertEqual(len(expected), len(actual))
    self.assertEqual(expected, actual)

  def testUnicode32NoSurrogate(self):
    fdp = atheris.FuzzedDataProvider(UTF32_BYTEMARK + b"dc\x0e\0" + b"4321" +
                                     HIGH_SURROGATE + b"\0\0" + LOW_SURROGATE +
                                     b"\0\0" + b"\xd1")

    chunk1 = b"dc\x0e\0".decode("utf-32")
    chunk2 = codepoint(0x31323334 & 0x10ffff)
    chunk3 = codepoint(0xDAA1 - 0xd800)
    chunk4 = codepoint(0xDD03 - 0xd800)

    expected = (chunk1 + chunk2 + chunk3 + chunk4)

    actual = fdp.ConsumeUnicodeNoSurrogates(atheris.ALL_REMAINING)
    for i in range(len(actual)):
      self.assertEqual(ord(expected[i]), ord(actual[i]))
    self.assertEqual(len(expected), len(actual))
    self.assertEqual(expected, actual)

  def testBytes(self):
    expected = b"abc123\0\0xff\0x7f\0x80"
    fdp = atheris.FuzzedDataProvider(expected)

    self.assertEqual(expected, fdp.ConsumeBytes(atheris.ALL_REMAINING))

  def testString(self):
    if sys.version_info[0] >= 3:
      fdp = atheris.FuzzedDataProvider(ASCII_BYTEMARK + b"abc" +
                                       ASCII_BYTEMARK + b"123")
      self.assertEqual("abc", fdp.ConsumeString(3))
      self.assertEqual("123", fdp.ConsumeString(atheris.ALL_REMAINING))
    else:
      fdp = atheris.FuzzedDataProvider(b"abc123")
      self.assertEqual("abc", fdp.ConsumeString(3))
      self.assertEqual("123", fdp.ConsumeString(atheris.ALL_REMAINING))

  def testInt1(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(1), 0x01)

  def testUInt1(self):
    fdp = atheris.FuzzedDataProvider(b"\xe1\x02\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeUInt(1), 0xe1)

  def testNegInt1(self):
    fdp = atheris.FuzzedDataProvider(b"\x81\x02\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(1), 0x81 - 0x100)

  def testInt2(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(2), 0x0201)

  def testUInt2(self):
    fdp = atheris.FuzzedDataProvider(b"\xa1\xe2\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeUInt(2), 0xe2a1)

  def testNegInt2(self):
    fdp = atheris.FuzzedDataProvider(b"\x10\x82\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(2), 0x8210 - 0x10000)

  def testInt3(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(3), 0x030201)

  def testUInt3(self):
    fdp = atheris.FuzzedDataProvider(b"\xa1\xb2\xc3\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeUInt(3), 0xc3b2a1)

  def testNegInt3(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\xd3\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(3), 0xd30201 - 0x1000000)

  def testInt4(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(4), 0x4030201)

  def testUInt4(self):
    fdp = atheris.FuzzedDataProvider(b"\xa1\xb2\xc3\xd4\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeUInt(4), 0xd4c3b2a1)

  def testNegInt4(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\x03\xe4\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(4), 0xe4030201 - 0x100000000)

  def testInt8(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    self.assertEqual(fdp.ConsumeInt(8), 0x0807060504030201)

  def testNegInt8(self):
    fdp = atheris.FuzzedDataProvider(b"\x01\x02\x03\x04\x05\x06\x07\xb8")
    self.assertEqual(
        fdp.ConsumeInt(8), 0xb807060504030201 - 0x10000000000000000)

  def testInt9(self):
    fdp = atheris.FuzzedDataProvider(
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a")
    self.assertEqual(fdp.ConsumeInt(9), 0x090807060504030201)

  def testNegInt9(self):
    fdp = atheris.FuzzedDataProvider(
        b"\x01\x02\x03\x04\x05\x06\x07\x08\xe9\x0a")
    self.assertEqual(
        fdp.ConsumeInt(9), 0xe90807060504030201 - 0x1000000000000000000)

  def testUInt9(self):
    fdp = atheris.FuzzedDataProvider(
        b"\xa1\xb2\xc3\xd4\xe5\xf6\xa7\xb8\xc9\xda")
    self.assertEqual(fdp.ConsumeUInt(9), 0xc9b8a7f6e5d4c3b2a1)

  def testInRange1(self):
    arr = b""
    for _ in range(0, 1000):
      arr += to_bytes(random.randint(0, 255), 1)
    fdp = atheris.FuzzedDataProvider(arr)

    for _ in range(0, 1000):
      one = random.randint(0, 255)
      two = random.randint(0, 255)
      if two >= one:
        result = fdp.ConsumeIntInRange(one, two)
        self.assertGreaterEqual(result, one)
        self.assertLessEqual(result, two)
      else:
        result = fdp.ConsumeIntInRange(two, one)
        self.assertGreaterEqual(result, two)
        self.assertLessEqual(result, one)

  def testInRange9(self):
    arr = b""
    for _ in range(0, 1000):
      arr += to_bytes(random.randint(0, 255), 1)
    fdp = atheris.FuzzedDataProvider(arr)

    for _ in range(0, 1000):
      one = random.randint(2**64, 2**72)
      two = random.randint(2**64, 2**72)
      if two >= one:
        result = fdp.ConsumeIntInRange(one, two)
        self.assertGreaterEqual(result, one)
        self.assertLessEqual(result, two)
      else:
        result = fdp.ConsumeIntInRange(two, one)
        self.assertGreaterEqual(result, two)
        self.assertLessEqual(result, one)

  def testIntList1(self):
    arr = b""
    for _ in range(0, 1000):
      arr += to_bytes(random.randint(0, 255), 1)
    fdp = atheris.FuzzedDataProvider(arr)

    l = fdp.ConsumeIntList(4321, 1)
    self.assertLen(l, 4321)
    for i in range(0, 1000):
      if arr[i] < 0:
        arr[i] += 256
      if l[i] < 0:
        l[i] += 256
      if sys.version_info[0] >= 3:
        self.assertEqual(arr[i], l[i])
      else:
        self.assertEqual(ord(arr[i]), l[i])

    for i in range(1000, 4321):
      self.assertEqual(l[i], 0)

  def testIntList9(self):
    arr = b""
    for _ in range(0, 1000):
      arr += to_bytes(random.randint(0, 2**72 - 1), 9)
    fdp = atheris.FuzzedDataProvider(arr)

    l = fdp.ConsumeIntList(4321, 9)
    self.assertLen(l, 4321)

    for i in range(0, 1000):
      self.assertGreaterEqual(l[i], -2**71)
      self.assertLessEqual(l[i], 2**71 - 1)

    for i in range(1000, 4321):
      self.assertEqual(l[i], 0)

  def testNonInfiniteFloat(self):
    arr = []
    arr.append(50)
    arr.append(152)
    arr.append(217)
    arr.append(85)
    arr.append(209)
    arr.append(188)
    arr.append(146)
    arr.append(14)
    arr.append(201)
    arr.append(240)
    arr = b"".join([to_bytes(x, 1) for x in arr])

    fdp = atheris.FuzzedDataProvider(arr)
    val = fdp.ConsumeFloat()
    self.assertGreaterEqual(val, -1.7976931348623157e+308)
    self.assertLessEqual(val, 1.7976931348623157e+308)

  def testFloatList(self):
    arr = b""
    for i in range(0, 256):
      arr += to_bytes(i, 1)
      arr += to_bytes(random.getrandbits(72), 9)

    fdp = atheris.FuzzedDataProvider(arr)

    pos_zero = fdp.ConsumeFloat()
    self.assertEqual(pos_zero, 0.0)
    self.assertNotEqual(str(pos_zero)[0], "-")

    neg_zero = fdp.ConsumeFloat()
    self.assertEqual(neg_zero, 0.0)
    self.assertEqual(str(neg_zero)[0], "-")

    pos_inf = fdp.ConsumeFloat()
    self.assertTrue(math.isinf(pos_inf))
    self.assertGreater(pos_inf, 0.0)

    neg_inf = fdp.ConsumeFloat()
    self.assertTrue(math.isinf(neg_inf))
    self.assertLess(neg_inf, 0)

    nan = fdp.ConsumeFloat()
    self.assertTrue(math.isnan(nan))

    pos_denorm_min = fdp.ConsumeFloat()
    self.assertLess(pos_denorm_min, 1e-323)
    self.assertGreater(pos_denorm_min, 0)

    neg_denorm_min = fdp.ConsumeFloat()
    self.assertGreater(neg_denorm_min, -1e-323)
    self.assertLess(neg_denorm_min, 0)

    pos_regular_min = fdp.ConsumeFloat()
    self.assertLess(pos_regular_min, 2.3e-308)
    self.assertGreater(pos_regular_min, 2.1e-308)

    neg_regular_min = fdp.ConsumeFloat()
    self.assertGreater(neg_regular_min, -2.3e-308)
    self.assertLess(neg_regular_min, -2.1e-308)

    pos_max = fdp.ConsumeFloat()
    self.assertGreater(pos_max, 1.79769313e+308)

    neg_max = fdp.ConsumeFloat()
    self.assertLess(neg_max, -1.79769313e+308)

    for _ in range(11, 256):
      val = fdp.ConsumeFloat()
      self.assertGreater(val, -1.79769313e+308)
      self.assertLess(val, 1.79769313e+308)

  def testPickValueInList1(self):
    l = [3, 3]

    arr = to_bytes(random.getrandbits(1024), int(1024 / 8))
    arr = to_bytes(1234, 8) + arr

    fdp = atheris.FuzzedDataProvider(arr)
    for _ in range(0, int(1024 / 8)):
      self.assertEqual(fdp.PickValueInList(l), 3)
    self.assertEqual(fdp.ConsumeIntInRange(0, 2**64 - 1), 1234)

    self.assertEqual(fdp.PickValueInList(l), 3)

  def testPickValueInList7(self):
    l = [4, 17, 52, 12, 8, 71, 2]
    s = set()

    arr = to_bytes(random.getrandbits(1024 * 1024), int(1024 * 1024 / 8))
    fdp = atheris.FuzzedDataProvider(arr)

    for _ in range(0, int(1024 * 1024 / 8)):
      s.add(fdp.PickValueInList(l))

    self.assertEqual(s, set(l))
    self.assertEqual(fdp.PickValueInList(l), 4)

  def testPickValueInListShort(self):
    l = []
    for i in range(1, 10001):
      l.append(i * 13)

    arr = to_bytes(random.getrandbits(1024 * 1024), int(1024 * 1024 / 8))
    fdp = atheris.FuzzedDataProvider(arr)

    all_returned = set()
    for i in range(0, 10000):
      val = fdp.PickValueInList(l)
      self.assertEqual(val % 13, 0)
      all_returned.add(val)

    self.assertGreater(len(all_returned), 200)


if __name__ == "__main__":
  googletest.main()

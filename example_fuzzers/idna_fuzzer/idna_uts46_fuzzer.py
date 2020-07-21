#!/usr/bin/python3
# coding=utf-8

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


""" IDNA encoding/decoding differential fuzzer for Python idna vs libidn2

This is a differential fuzzer that compares the Python `idna` package with the
`libidn2` package. It only considers situations where both libraries consider a
domain to be valid, but produce different results. libidn2 is called via a thin
wrapper that defines libidn2 Python bindings.
This fuzzer enables UTS#46 translation (a feature that transforms certain
invalid characters into valid ones), and fuzzes against other encoding options.

To run this fuzzer, you'll need to install a thin wrapper to make libidn2
callable from Python; install libidn2, then cd to `libidn2_wrapper/` and run
`pip3 install .`.

This fuzzer found a number of domains which encode differently in Python `idna`
vs. `libidn2`. The fuzzer was designed to find mistakes in the Python idna
package, but actually found problems with libidn2.

As an example, `a.İ᷹` (codepoints `['61', '2e', '130', '1df9']`) encodes to the
Punycode `a.xn--i-9bb708r` in Python, but `a.xn--i-9bb808r` in libidn2. This
error occurs because libidn2 supports Unicode 11 and therefore accepts the
domain as valid; but it relies on `libunistring`, which only supports
Unicode 9 and therefore produces incorrect metadata about Unicode 11 characters.
"""
import atheris
import idna
import sys
import unicodedata

import libidn2


def TestOneInput(input_bytes):
  global total_iters
  global comparison_iters
  fdp = atheris.FuzzedDataProvider(input_bytes)

  transitional = fdp.ConsumeBool()
  std3 = fdp.ConsumeBool()
  original = "a." + fdp.ConsumeUnicode(253)

  try:
    nfc_original = unicodedata.normalize("NFC", original)
    libidn2_encoded = libidn2.encode(
        original,
        uts46=True,
        transitional=transitional,
        nfc=True,
        std3=std3)
    idna_encoded = idna.encode(
        original,
        strict=False,
        uts46=True,
        transitional=transitional,
        std3_rules=std3).lower()
  except Exception as e:
    return

  if idna_encoded != libidn2_encoded:
    sys.stderr.write("Transitional=%s, std3=%s\n" % (transitional, std3))
    sys.stderr.write("Input codepoints:    %s\n" %
                     [hex(ord(x))[2:] for x in original])
    raise RuntimeError(
        "IDNA encoding disagrees with libidn2 encoding.\nInput: %s\nIDNA encoding:    %s\nlibidn2 encoding: %s\n"
        % (original, idna_encoded, libidn2_encoded))

  idna_decoded = idna.decode(idna_encoded, uts46=True, std3_rules=std3)
  libidn2_decoded = libidn2.decode(idna_encoded, uts46=True, std3=std3)

  if idna_decoded != libidn2_decoded:
    raise RuntimeError(
        "IDNA decoding disagrees with libidn2 decoding.\nInput: %s\nEncoding: %s\nIDNA decoding:    %s\nlibidn2 decoding: %s"
        % (original, idna_encoded, idna_decoded, libidn2_decoded))


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()

if __name__ == "__main__":
  main()

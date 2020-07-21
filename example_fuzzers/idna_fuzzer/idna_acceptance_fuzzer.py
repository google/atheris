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


"""IDNA encoding/decoding differential fuzzer for Python idna vs libidn2.

This is a differential fuzzer that compares the Python `idna` package with the C
`libidn2` package. Unlike idna_uts46_fuzzer.py, it looks primarily for whether
a domain is valid or not.

To run this fuzzer, you'll need to install a thin wrapper to make libidn2
callable from Python; install libidn2, then cd to `libidn2_wrapper/` and run
`pip3 install .`.

This has found several situations where valid domains are rejected by libidn2,
including :
 -
 `髦暩晦晦晦獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳筳獳싂.퐀쓄쓄쓄쓄쓄쓄쓄쓄쓄쓄쓄쓼쓄쓄쓄쓄쓄쓄쓄쓄쓄㻄쓄쓄럄䄀싂.뼀猀獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳獳ⱁ㩁`
   libidn2 reports "domain too long", but it is not.
 - `ਗ਼.ÿ߽̃̃̃` (hex codepoints: ['a17', 'a3c', '2e', 'ff', '7fd', '303', '303',
 '303'])
   libidn2 reports "forbidden bidirectional properties", but the string is
   valid. This is likely because libidn2 uses Unicode 11, but relies on
   libunistring, which depends on Unicode 9. Therefore, it doesn't have correct
   bidirectional metadata some codepoints.
"""

import sys
import unicodedata

import atheris
import idna
import libidn2


def ShouldFail(domain):
  """Returns True for domains that we know are invalid, False otherwise."""
  if "." not in domain:
    return True
  pieces = domain.split(".")

  total_length = len(b".".join([piece.encode("punycode") for piece in pieces]))
  if total_length > 253:
    return True

  for piece in pieces:
    # Iteration over each label in the domain, checking various requirements.
    if len(piece) == 0:
      return True
    if len(piece) > 63:
      return True
    if len(piece.encode("punycode")) > 59:
      return True
    # Domain labels must not start with a -, end with a -, or have both their
    # third and fourth characters be --.
    if piece.startswith("-"):
      return True
    if piece.endswith("-"):
      return True
    if len(piece) >= 4 and piece[2] == "-" and piece[3] == "-":
      return True
    if len(piece) and unicodedata.category(piece[0])[0] == "M":
      return True

    # Bidirectional checks (ensures that the label follows the "bidi rule"
    # for IDNA)
    direction = unicodedata.bidirectional(piece[0])
    if direction in ["R", "AL"]:
      rtl = True
    elif direction == "L":
      rtl = False
    else:
      return True
    if rtl:
      has_en = False
      has_an = False
      for c in piece:
        biditype = unicodedata.bidirectional(c)
        if biditype not in [
            "R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"
        ]:
          return True
        if biditype == "EN":
          has_en = True
        if biditype == "AN":
          has_an = True
      if has_en and has_an:
        return True
      for i in range(len(piece) - 1, 0 - 1, -1):
        biditype = unicodedata.bidirectional(piece[i])
        if biditype in ["R", "AL", "EN", "AN"]:
          break
        if biditype != "NSM":
          return True

    else:
      for c in piece:
        if unicodedata.bidirectional(c) not in [
            "L", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"
        ]:
          return True
      for i in range(len(piece) - 1, 0 - 1, -1):
        biditype = unicodedata.bidirectional(piece[i])
        if biditype in ["L", "EN"]:
          break
        if biditype != "NSM":
          return True
  return False


def CompareEncodedWithLibidn2(original, encoded):
  """Encodes `original` with libidn2 and compares it to `encoded`."""
  try:
    libidn2_encoded = libidn2.encode(original)
  except RuntimeError as e:
    # libidn2 only supports Unicode 11, which might mean it doesn't accept a
    # character that Python accepts. That's fine.
    if str(e).startswith("RuntimeError: string contains a disallowed "):
      return

    codepoints = [hex(ord(x))[2:] for x in original]
    sys.stderr.write((
        "IDNA produced a valid output, whereas libidn2 returned an error.\n"
        "Input: %s\nInput codepoints: %s\nIDNA encoding: %s\n"
        "libidn2 decoding of IDNA encoding:%s\n")
        % (original, codepoints, encoded, libidn2.decode(encoded)))
    raise

  if encoded != libidn2_encoded:
    raise RuntimeError((
        "IDNA encoding disagrees with libidn2 encoding.\nInput: %s\n"
        "IDNA encoding: %s\nlibidn2 encoding: %s")
        % (original, encoded, libidn2_encoded))


def CompareDecodedWithLibidn2(original, encoded, decoded):
  """Decodes `encoded` with libidn2, and compares it to `decoded` from idna."""
  libidn2_decoded = libidn2.decode(encoded)
  if libidn2_decoded != decoded:
    raise RuntimeError((
        "IDNA decoding disagrees with libidn2 decoding.\nOriginal Input: %s\n"
        "Encoding: %s\nIDNA Decoding: %s\nlibidn2 Decoding: %s\n")
        % (original, encoded, decoded, libidn2_decoded))


def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  original = fdp.ConsumeUnicode(253)
  original = unicodedata.normalize("NFC", original)

  should_fail = ShouldFail(original)

  try:
    encoded = idna.encode(original, strict=True).lower()

    if should_fail:
      raise RuntimeError(
          ("Input '%s' is invalid, should have failed; "
           "however, actually encoded to '%s'")
          % (original, encoded))
  # These errors are very complex would essentially require the idna package to
  # be reimplemented in order to correctly implement, so we assume they are
  # valid.
  except idna.core.InvalidCodepoint as e:
    return
  except idna.core.InvalidCodepointContext as e:
    return

  except idna.core.IDNAError as e:
    if str(e).startswith("Unknown codepoint adjacent to"):
      return

    if should_fail:
      return
    codepoints = [ord(x) for x in original.lower()]
    sys.stderr.write("Input: %s\nCodepoints: %s\n" % (original, codepoints))
    raise
  except BaseException as e:
    if should_fail:
      return
    codepoints = [ord(x) for x in original.lower()]
    sys.stderr.write("Input: %s\nCodepoints: %s\n" % (original, codepoints))
    raise
  decoded = idna.decode(encoded)

  CompareEncodedWithLibidn2(original, encoded)
  CompareDecodedWithLibidn2(original, encoded, decoded)


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()

if __name__ == "__main__":
  main()

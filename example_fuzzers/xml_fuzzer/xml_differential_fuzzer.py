#!/usr/bin/python3

# Copyright 2023 Google LLC
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
"""An example ElementTree vs minidom differential fuzzer.

This fuzzer looks for differences between the ElementTree library
parser and the minidom library parser.
"""

from xml.dom import minidom
from xml.etree import ElementTree

import atheris


with atheris.instrument_imports():
  import sys
  import xmltodict
  import xml


@atheris.instrument_func
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  data = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)

  et_root = None
  minidom_root = None

  et_parse_error = False
  minidom_parse_error = False

  try:
    et_root = ElementTree.fromstring(data)
  except ElementTree.ParseError:
    et_parse_error = True
  except Exception:
    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stderr.write(
        "Input was {input_type}: {data}\nCodepoints: {codepoints}".format(
            input_type=input_type, data=data, codepoints=codepoints))
    raise

  try:
    minidom_root = minidom.parseString(data)
  except xml.parsers.expat.ExpatError:
    minidom_parse_error = True
  except Exception:
    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stderr.write(
        "Input was {input_type}: {data}\nCodepoints: {codepoints}".format(
            input_type=input_type, data=data, codepoints=codepoints))
    raise

  # Check for parse error discrepancies
  if et_parse_error and minidom_parse_error:
    return
  elif et_parse_error and not minidom_parse_error:
    raise RuntimeError(
        "ET parse error but no minidom parse error!\nInput: %s"
        % (data,))
  elif not et_parse_error and minidom_parse_error:
    raise RuntimeError(
        "minidom parse error but no ET parse error!\nInput: %s"
        % (data,))

  # Now convert both xml objects to dictionaries to compare
  et_str = ElementTree.tostring(et_root, encoding="unicode")
  minidom_str = minidom_root.toxml()
  et_dict = xmltodict.parse(et_str)
  minidom_dict = xmltodict.parse(minidom_str)
  if et_dict != minidom_dict:
    raise RuntimeError(
        "Decoding/encoding disagreement!\nInput: %s\nET data: %s\nminidom data: %s\nET dict: %s\nminidom dict: %s\n"
        % (data, et_str, minidom_str, et_dict, minidom_dict))


def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()


if __name__ == "__main__":
  main()

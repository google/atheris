#!/usr/bin/python3

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

"""This fuzzer is an example of looking for weird exceptions in ruamel.yaml.

While these do not necessarily indicate vulnerabilities, they often indicate
other bugs in code.
Two bugs found by this fuzzer include situations where ruamel.yaml tries
inserting lists/dicts as *keys* in maps, which is invalid JSON and causes a
ValueError to be raised. The worst consequences of this is likely
denial-of-service for code that only expects a YAMLError to be raised; however,
it may indicate more interesting parsing problems.
"""
import sys
import warnings

import atheris
from ruamel import yaml as ruamel_yaml

# Suppress all warnings.
warnings.simplefilter("ignore")

ryaml = ruamel_yaml.YAML(typ="safe", pure=True)
ryaml.allow_duplicate_keys = True


def TestOneInput(input_bytes):
  fdp = atheris.FuzzedDataProvider(input_bytes)
  data = fdp.ConsumeUnicode(sys.maxsize)

  try:
    iterator = ryaml.load_all(data)
    for _ in iterator:
      pass
  except ruamel_yaml.error.YAMLError:
    return

  except Exception:
    input_type = str(type(data))
    codepoints = [hex(ord(x)) for x in data]
    sys.stderr.write(
        "Input was {input_type}: {data}\nCodepoints: {codepoints}".format(
            input_type=input_type, data=data, codepoints=codepoints))
    raise


def main():
  atheris.Setup(sys.argv, TestOneInput)
  atheris.Fuzz()

if __name__ == "__main__":
  main()

# Copyright 2021 Google Inc.
# Copyright 2021 Fraunhofer FKIE
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

from .native import Setup, Fuzz, FuzzedDataProvider, _trace_branch, _reserve_counters, _trace_cmp, ALL_REMAINING
from .import_hook import instrument_imports
from .instrument_bytecode import patch_code, instrument_func, instrument_all
from .utils import path

# PyInstaller Support
# PyInstaller doesn't automatically support lazy imports, which happens because
# we dynamically decide whether to import the with/without_libfuzzer versions of
# the core module. This function tells it where to look for a hook-atheris.py
# file.

def get_hook_dirs():
  import os
  return [os.path.dirname(__file__)]

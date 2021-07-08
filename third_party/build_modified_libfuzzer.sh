#!/bin/bash
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

set -e -x

# Move to the correct working dir
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "PWD: $PWD"

# Fetch the Python source repo.
git clone https://github.com/python/cpython
(
  # Switch to version 3.8.6.
  cd cpython;
  git fetch --all --tags;
  git checkout tags/v3.8.6 -b 3.8.6;

  git apply "../cpython-3.8.6-add-libFuzzer.patch"

  # We need to know where libFuzzer is. Atheris generates one on installation;
  # use that.
  if [ -z "$LIBFUZZER_VERSION" ]; then

    export LIBFUZZER_VERSION="$(python3 -c "
try:
  import atheris;
except ImportError:
  import sys;
  sys.stderr.write('Cannot find libFuzzer because Atheris is not installed. Either install Atheris before running this script, or set LIBFUZZER_VERSION');
  raise;
import os;
import glob;
dir=os.path.dirname(atheris.path());
libfuzzers=glob.glob(dir+'/libclang_rt.fuzzer_no_main*');
if len(libfuzzers) != 1:
  raise RuntimeError('Failed to definitively find libFuzzer; please set LIBFUZZER_VERSION.');
print(libfuzzers[0]);
")"
  fi

  # Build.
  ./configure
  make -j 100
)

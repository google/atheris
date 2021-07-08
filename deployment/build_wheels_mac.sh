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

# This script requires that 'python36', 'python37', 'python38', and 'python39'
# be present on the path, and that $CLANG_BIN be set to the location of a
# built-from-source Clang.

set -e -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR/../"

if [[ -z "${CLANG_BIN}" ]]; then
  echo 'Please set $CLANG_BIN to point to a Clang built from source.' 2>&1
  exit 1
fi

export CC="${CLANG_BIN}"
export CXX="${CLANG_BIN}++"


python36 setup.py bdist_wheel -d ./dist
python37 setup.py bdist_wheel -d ./dist
python38 setup.py bdist_wheel -d ./dist
python39 setup.py bdist_wheel -d ./dist

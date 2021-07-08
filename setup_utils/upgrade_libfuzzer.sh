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

# At the time of this writing, Atheris requires a very new (unreleased) version
# of libFuzzer. We expect very few people to have this version. However, it's
# possible to do an in-place upgrade of libFuzzer by adding a thin wrapper into
# the archive. Let's do that.

set -e

libfuzzer="$1"
tmp_libfuzzer="$(mktemp --suffix=.a)"
tmp_wrapper="$(mktemp --suffix=.o)"

objcopy --globalize-symbol=_ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE \
          "$libfuzzer" \
          "$tmp_libfuzzer"

if [ -z "$CXX" ]; then
  export CXX="clang++"
fi

(
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
  cd "$DIR"
  "$CXX" fuzzer_run_driver_wrapper.cc -c -o "$tmp_wrapper"
)
ar r "$tmp_libfuzzer" "$tmp_wrapper"

echo "$tmp_libfuzzer"
exit 0

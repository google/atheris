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
# possible to do an in-place upgrade of libFuzzer just by fiddling with a symbol
# in the archive. This script attempts to do that.

set -e

libfuzzer="$1"
tmpfile_1="$(mktemp --suffix=.a)"
tmpfile_2="$(mktemp --suffix=.a)"

objcopy --redefine-sym=_ZN6fuzzer12FuzzerDriverEPiPPPcPFiPKhmE=LLVMFuzzerRunDriver \
          "$libfuzzer" \
          "$tmpfile_1"

objcopy --globalize-symbol=LLVMFuzzerRunDriver \
          "$tmpfile_1" \
          "$tmpfile_2"

echo "$tmpfile_2"
exit 0

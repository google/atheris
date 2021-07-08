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


# This script examines a libFuzzer .a to determine whether it is a sufficiently
# high version to work with Atheris. If the symbol LLVMFuzzerRunDriver appears,
# we're good. If it doesn't, then we can attempt an upgrade (see
# upgrade_libfuzzer.h). If __sanitizer_cov_8bit_counters_init also doesn't
# appear, then this is a very old version of libFuzzer, and we can't use it at
# all.

set -e

libfuzzer="$1"

if objdump -t "$libfuzzer" | grep "LLVMFuzzerRunDriver" > /dev/null; then
  echo "up-to-date"
else
  if objdump -t "$libfuzzer" | grep "__sanitizer_cov_8bit_counters_init" > /dev/null; then
    echo "outdated-recoverable"
  else
    echo "outdated-unrecoverable"
  fi
fi

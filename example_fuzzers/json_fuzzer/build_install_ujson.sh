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

# This is an example - You might need to change some parameters. This builds
# ujson with coverage and Address Sanitizer.
git clone https://github.com/ultrajson/ultrajson
(
  cd ultrajson;
  CC="/usr/bin/clang" CFLAGS="-fsanitize=fuzzer-no-link,address" CXX="/usr/bin/clang++" CXXFLAGS="-fsanitize=fuzzer-no-link,address" pip3 install .
)

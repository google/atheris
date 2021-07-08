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


# This script iteratively searches Clang library dirs for the libFuzzer archive.
set -e

uname="$(uname)"

if [[ "$uname" == "Darwin" ]]; then
  libpath="lib/darwin/libclang_rt.fuzzer_no_main_osx.a"
elif [[ "$uname" == "Linux" ]]; then
  machine="$(uname -m)"
  if [[ "$machine" == "x86_64" ]]; then
    libpath="lib/linux/libclang_rt.fuzzer_no_main-x86_64.a"
  elif [[ "$machine" == "i386" ]]; then
    libpath="lib/linux/libclang_rt.fuzzer_no_main-i386.a"
  elif [[ "$machine" == "i686" ]]; then
    libpath="lib/linux/libclang_rt.fuzzer_no_main-i386.a"
  else
    >&2 echo "Failed to identify platform machine (got $machine); set \$LIBFUZZER_LIB to point directly to your libfuzzer .a file."
  fi
else
  >&2 echo "Failed to identify platform (got $uname); set \$LIBFUZZER_LIB to point directly to your libfuzzer .a file."
fi

if [ ! -z "$CLANG_BIN" ]; then
  search_dirs="$("$CLANG_BIN" -print-search-dirs | grep "^libraries: =")"
else
  search_dirs="$(clang -print-search-dirs | grep "^libraries: =")"
fi
search_dirs="${search_dirs/libraries: =}"
search_dirs="$(echo $search_dirs | tr ":" "\n")"

while IFS= read -r line; do
  path="$line/$libpath"
  if [[ -f "$path" ]]; then
    echo -n "$path"
    exit 0
  fi
done <<< "$search_dirs"

>&2 echo "Failed to find libFuzzer archive in search path $search_path"
exit 1

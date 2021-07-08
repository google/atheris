// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a thin wrapper that can be linked with old versions of libFuzzer to
// add support for the new LLVMFuzzerRunDriver API.

#include <cstdint>

namespace fuzzer {
typedef int (*UserCallback)(const uint8_t *Data, std::size_t Size);
int FuzzerDriver(int *argc, char ***argv, UserCallback Callback);
}  // namespace fuzzer

extern "C" __attribute__((visibility("default"))) int
LLVMFuzzerRunDriver(int *argc, char ***argv,
                    int (*UserCb)(const uint8_t *Data, std::size_t Size)) {
  return fuzzer::FuzzerDriver(argc, argv, UserCb);
}

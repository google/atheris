/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "third_party/py/atheris/src/mock_libfuzzer/mock_libfuzzer_lib.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#ifndef MOCK_LIBFUZZER
#error \
    "Atheris must be built with mock_libfuzzer to run this test. " \
    "In google3, use Blaze flag --define=FUZZING_ENGINE=atheris_mock."
#endif

int default_LLVMFuzzerRunDriver(int* argc, char*** argv,
                                int (*UserCb)(const uint8_t* Data,
                                              size_t Size)) {
  uint8_t data;
  UserCb(&data, 0);
  std::cerr << "LLVMFuzzerRunDriver ran once." << std::endl;
  exit(1);
}
size_t default_LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize) {
  return Size;
}

void default_sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop) {}
void default_sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end) {}

void default_sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {}
void default_sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {}
void default_sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                        const void* s2, size_t n, int result) {}

int (*mock_LLVMFuzzerRunDriver)(int* argc, char*** argv,
                                int (*UserCb)(const uint8_t* Data,
                                              size_t Size)) =
    &default_LLVMFuzzerRunDriver;
size_t (*mock_LLVMFuzzerMutate)(uint8_t* Data, size_t Size,
                                size_t MaxSize) = &default_LLVMFuzzerMutate;

void (*mock_sanitizer_cov_8bit_counters_init)(uint8_t* start, uint8_t* stop) =
    &default_sanitizer_cov_8bit_counters_init;
void (*mock_sanitizer_cov_pcs_init)(uint8_t* pcs_beg, uint8_t* pcs_end) =
    &default_sanitizer_cov_pcs_init;

void (*mock_sanitizer_cov_trace_const_cmp8)(uint64_t arg1, uint64_t arg2) =
    &default_sanitizer_cov_trace_const_cmp8;
void (*mock_sanitizer_cov_trace_cmp8)(uint64_t arg1, uint64_t arg2) =
    &default_sanitizer_cov_trace_cmp8;
void (*mock_sanitizer_weak_hook_memcmp)(void* caller_pc, const void* s1,
                                        const void* s2, size_t n, int result) =
    &default_sanitizer_weak_hook_memcmp;

extern "C" {
int LLVMFuzzerRunDriver(int* argc, char*** argv,
                        int (*UserCb)(const uint8_t* Data, size_t Size)) {
  return mock_LLVMFuzzerRunDriver(argc, argv, UserCb);
}
size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize) {
  return mock_LLVMFuzzerMutate(Data, Size, MaxSize);
}
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop) {
  mock_sanitizer_cov_8bit_counters_init(start, stop);
}
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end) {
  mock_sanitizer_cov_pcs_init(pcs_beg, pcs_end);
}

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {
  mock_sanitizer_cov_trace_const_cmp8(arg1, arg2);
}
void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {
  mock_sanitizer_cov_trace_cmp8(arg1, arg2);
}
void __sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                  const void* s2, size_t n, int result) {
  mock_sanitizer_weak_hook_memcmp(caller_pc, s1, s2, n, result);
}
}

namespace fuzzer {
int FuzzerDriver(int* argc, char*** argv,
                 int (*UserCb)(const uint8_t* Data, size_t Size)) {
  return LLVMFuzzerRunDriver(argc, argv, UserCb);
}
}  // namespace fuzzer
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

// Any of the function pointers declared here can be set to point to a mock
// implementation of the corresponding function. Each is initialized with a
// no-op implementation, except LLVMFuzzerRunDriver, which aborts (as the normal
// implementation of that function never returns).

#ifndef ATHERIS_TRACER_H_
#define ATHERIS_TRACER_H_

#include <cstddef>
#include <cstdint>

extern int (*mock_LLVMFuzzerRunDriver)(int* argc, char*** argv,
                                       int (*UserCb)(const uint8_t* Data,
                                                     size_t Size));
extern size_t (*mock_LLVMFuzzerMutate)(uint8_t* Data, size_t Size,
                                       size_t MaxSize);

extern void (*mock_sanitizer_cov_8bit_counters_init)(uint8_t* start,
                                                     uint8_t* stop);
extern void (*mock_sanitizer_cov_pcs_init)(uint8_t* pcs_beg, uint8_t* pcs_end);

extern void (*mock_sanitizer_cov_trace_const_cmp8)(uint64_t arg1,
                                                   uint64_t arg2);
extern void (*mock_sanitizer_cov_trace_cmp8)(uint64_t arg1, uint64_t arg2);
extern void (*mock_sanitizer_weak_hook_memcmp)(void* caller_pc, const void* s1,
                                               const void* s2, size_t n,
                                               int result);

int default_LLVMFuzzerRunDriver(int* argc, char*** argv,
                                int (*UserCb)(const uint8_t* Data,
                                              size_t Size));
size_t default_LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);

void default_sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
void default_sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);

void default_sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2);
void default_sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);
void default_sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                        const void* s2, size_t n, int result);

#endif  // ATHERIS_TRACER_H_

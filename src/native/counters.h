/*
 * Copyright 2021 Google LLC
 * Copyright 2021 Fraunhofer FKIE
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
// This module manages the global counters given to the backend sanitizer.
//
// We preallocate the maximum number of counters when we first start fuzzing.
// max_counters may be redefined via flag at that point too. We only tell
// libfuzzer about this memory at the start of test_one_input, if new counters
// were added.
//
// If more than max_counters were registered, we'll wrap around to the start and
// reuse existing counters. This lowers fuzzing quality. Its easier book keeping
// to have it all in one array, and we need fast lookups for _trace_branch. Note
// that we fill this array from low addresses going up. Un-written-to pages will
// only cost virtual memory, VSS not RSS, so preallocating lots of memory is ok.

#ifndef THIRD_PARTY_PY_ATHERIS_SRC_NATIVE_COUNTERS_H_
#define THIRD_PARTY_PY_ATHERIS_SRC_NATIVE_COUNTERS_H_

namespace atheris {

struct PCTableEntry {
  void* pc;
  long flags;
};

// Sets the global number of counters.
// Must not be called after InitializeCountersWithLLVM is called.
// TODO(b/207008147): Expose this to Atheris users.
void SetMaxCounters(int max);

// Returns the maximum number of allocatable Atheris counters. If more than this
// many counters are reserved, Atheris reuses counters, lowering fuzz quality.
int GetMaxCounters();

// Returns a new counter index.
int ReserveCounter();
// Reserves a number of counters with contiguous indices, and returns the first
// index.
int ReserveCounters(int counters);

// Increments the counter at the given index. If more than the maximum number of
// counters has been reserved, reuse counters.
void IncrementCounter(int counter_index);

struct CounterAndPcTableRange {
  unsigned char* counters_start;
  unsigned char* counters_end;
  unsigned char* pctable_start;
  unsigned char* pctable_end;
};
// Returns pointers to a range of memory for counters and another for pctable.
// The intent is for this memory to be handed to Libfuzzer. It will only be
// deallocated by TestOnlyResetCounters. The size of the ranges is proportional
// to the number of counters reserved, unless no new counters were reserved or
// more than max_counters were already reserved, in which case returns nullptrs.
CounterAndPcTableRange AllocateCountersAndPcs();

// Resets counters' state to defaults. This is not safe for use with the actual
// fuzzer as, once fuzzing begins, the fuzzer is given access to the counters'
// memory. Unless you swapped out the fuzzer and know it will not access the
// previous counters and pctable entries again, you'll probably segfault.
void TestOnlyResetCounters();

}  // namespace atheris

#endif  // THIRD_PARTY_PY_ATHERIS_SRC_NATIVE_COUNTERS_H_

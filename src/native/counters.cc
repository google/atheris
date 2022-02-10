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
#include "counters.h"

#include <sys/mman.h>

#include <iostream>

#include "macros.h"

extern "C" {
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);
}

namespace atheris {

const int kDefaultNumCounters = 1 << 20;

// Number of counters requested by Python instrumentation.
int counter_index = 0;
// Number of counters given to Libfuzzer.
int counter_index_registered = 0;
// Maximum number of counters and pctable entries that may be reserved and also
// the number that are allocated.
int max_counters = 0;
// Counter Allocations. These are allocated once, before __sanitize_... are
// called and can only be deallocated by TestOnlyResetCounters.
unsigned char* counters = nullptr;
PCTableEntry* pctable = nullptr;

NO_SANITIZE
void TestOnlyResetCounters() {
  if (counters) {
    munmap(counters, max_counters);
    counters = nullptr;
  }
  if (pctable) {
    munmap(pctable, max_counters);
    pctable = nullptr;
  }
  max_counters = 0;
  counter_index = 0;
  counter_index_registered = 0;
}

NO_SANITIZE
int ReserveCounters(int counters) {
  int ret = counter_index;
  counter_index += counters;
  return ret;
}

NO_SANITIZE
int ReserveCounter() { return counter_index++; }

NO_SANITIZE
void IncrementCounter(int counter_index) {
  if (counters != nullptr && pctable != nullptr) {
    // `counters` is an allocation of length `max_counters`. If we reserve more
    // than the allocated number of counters, we'll wrap around and overload
    // old counters, trading away fuzzing quality for limits on memory usage.
    counters[counter_index % max_counters]++;
  }
}

NO_SANITIZE
void SetMaxCounters(int max) {
  if (counters != nullptr && pctable != nullptr) {
    std::cerr << "Atheris internal error: Tried to set max counters after "
              << "counters were passed to the sanitizer!\n";
    exit(1);
  }
  if (max < 1) exit(1);
  max_counters = max;
}

NO_SANITIZE
int GetMaxCounters() { return max_counters; }

NO_SANITIZE
CounterAndPcTableRange AllocateCountersAndPcs() {
  if (max_counters < 1) {
    SetMaxCounters(kDefaultNumCounters);
  }
  if (counter_index < counter_index_registered) {
    std::cerr << "Atheris internal fatal logic error: The counter index is "
              << "greater than the number of counters registered.\n";
    exit(1);
  }
  // Allocate memory.
  if (counters == nullptr || pctable == nullptr) {
    // We mmap memory for pctable and counters, instead of std::vector, ensuring
    // that there is no initialization. The untouched memory will only cost
    // virtual memory, which is cheap.
    counters = static_cast<unsigned char*>(
        mmap(nullptr, max_counters, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    pctable = static_cast<PCTableEntry*>(
        mmap(nullptr, max_counters * sizeof(PCTableEntry),
             PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    if (counters == MAP_FAILED || pctable == MAP_FAILED) {
      std::cerr << "Atheris internal error: Failed to mmap counters.\n";
      exit(1);
    }
  }

  const int next_index = std::min(counter_index, max_counters);
  if (counter_index_registered >= next_index) {
    // There are no counters to pass. Perhaps because we've reserved more than
    // max_counters, or because no counters have been reserved since this was
    // last called.
    counter_index_registered = counter_index;
    return CounterAndPcTableRange{nullptr, nullptr, nullptr, nullptr};
  } else {
    CounterAndPcTableRange ranges = {
        .counters_start = counters + counter_index_registered,
        .counters_end = counters + next_index,
        .pctable_start =
            reinterpret_cast<uint8_t*>(pctable + counter_index_registered),
        .pctable_end = reinterpret_cast<uint8_t*>(pctable + next_index)};
    counter_index_registered = counter_index;
    return ranges;
  }
}

}  // namespace atheris

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

// WARNING: The test, InitializeCountersRespectsMaxCounters, will fail if the
// `__sanitize_cov_..._init` symbols are defined (ODR violation). This may be
// caused by having a real fuzzer attached.

#include "counters.h"

#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

std::vector<int>& counter_inits = *new std::vector<int>();
std::vector<int>& pcs_inits = *new std::vector<int>();

extern "C" {
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop) {
  counter_inits.push_back((int)(stop - start));
}
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end) {
  pcs_inits.push_back((int)(pcs_end - pcs_beg) / sizeof(atheris::PCTableEntry));
}
}  // extern "C"

namespace {

class CountersTest : public testing::Test {
  void TearDown() override {
    atheris::TestOnlyResetCounters();
    counter_inits.clear();
    pcs_inits.clear();
  }
};

TEST_F(CountersTest, SetAndGetMaxCounters) {
  atheris::SetMaxCounters(1337);
  EXPECT_EQ(atheris::GetMaxCounters(), 1337);
  atheris::SetMaxCounters(8200);
  EXPECT_EQ(atheris::GetMaxCounters(), 8200);
}

TEST_F(CountersTest, SetMaxCountersAfterAllocatingAndDie) {
  atheris::AllocateCountersAndPcs();
  EXPECT_EXIT(atheris::SetMaxCounters(5), testing::ExitedWithCode(1),
              "Atheris internal error");
}

TEST_F(CountersTest, SetMaxCountersBeforeAllocatingAndLive) {
  atheris::SetMaxCounters(42);
  atheris::AllocateCountersAndPcs();
}

TEST_F(CountersTest, ReserveCountersIncrementsPastMaxCounters) {
  atheris::SetMaxCounters(5);
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(atheris::ReserveCounter(), i);
  }
}

TEST_F(CountersTest, NextCounterAndPcTableRange) {
  // Allocate space for 10 counters
  atheris::SetMaxCounters(10);

  // Register and allocate 8 of them.
  for (int i = 0; i < 8; i++) atheris::ReserveCounter();
  const auto range1 = atheris::AllocateCountersAndPcs();
  EXPECT_EQ(range1.counters_end - range1.counters_start, 8);
  EXPECT_EQ(range1.pctable_end - range1.pctable_start,
            8 * sizeof(atheris::PCTableEntry));

  // Register 0 counters, so nothing is allocated.
  const auto range2 = atheris::AllocateCountersAndPcs();
  EXPECT_EQ(range2.counters_start, nullptr);
  EXPECT_EQ(range2.counters_end, nullptr);
  EXPECT_EQ(range2.pctable_start, nullptr);
  EXPECT_EQ(range2.pctable_end, nullptr);

  // Register 8 more but only 2 more need to be allocated.
  for (int i = 0; i < 8; i++) atheris::ReserveCounter();
  const auto range3 = atheris::AllocateCountersAndPcs();
  EXPECT_EQ(range3.counters_end - range3.counters_start, 2);
  EXPECT_EQ(range3.pctable_end - range3.pctable_start,
            2 * sizeof(atheris::PCTableEntry));

  // Register 8 more counters but max has been reached, no allocation.
  for (int i = 0; i < 8; i++) atheris::ReserveCounter();
  const auto range4 = atheris::AllocateCountersAndPcs();
  EXPECT_EQ(range4.counters_start, nullptr);
  EXPECT_EQ(range4.counters_end, nullptr);
  EXPECT_EQ(range4.pctable_start, nullptr);
  EXPECT_EQ(range4.pctable_end, nullptr);
}

}  // namespace

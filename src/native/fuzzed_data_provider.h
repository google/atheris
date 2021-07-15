/*
 * Copyright 2020 Google LLC
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

#ifndef THIRD_PARTY_PY_ATHERIS_FUZZED_DATA_PROVIDER_H_
#define THIRD_PARTY_PY_ATHERIS_FUZZED_DATA_PROVIDER_H_

#include <Python.h>
#include <unicodeobject.h>

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iostream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "util.h"

namespace atheris {

namespace py = pybind11;

// A useful tool for generating various types of data from the arbitrary
// bytes produced by the fuzzer.
class FuzzedDataProvider {
 public:
  FuzzedDataProvider(py::bytes bytes)
      : data_ptr_(
            reinterpret_cast<const uint8_t *>(PyBytes_AsString(bytes.ptr()))),
        remaining_bytes_(PyBytes_Size(bytes.ptr())),
        ref_(bytes) {}
  ~FuzzedDataProvider() = default;

  // Consume count bytes.
  py::bytes ConsumeBytes(size_t count);

  // Consume unicode characters. Might contain surrogate pair characters,
  // which according to the specification are invalid in this situation.
  // However, many core software tools (e.g. Windows file paths) support them,
  // so other software often needs to too.
  py::object ConsumeUnicode(size_t count) {
    return ConsumeUnicodeImpl(count, /*filter_surrogates=*/false);
  }

  // Consume unicode characters, but never generate surrogate pair characters.
  py::object ConsumeUnicodeNoSurrogates(size_t count) {
    return ConsumeUnicodeImpl(count, /*filter_surrogates=*/true);
  }

  // Alias for Consume{Bytes,Unicode} depending on whether this is python 2 or 3
  py::object ConsumeString(size_t count);

  // Consumes a signed integer of the specified size (when written in two's
  // complement notation)
  py::int_ ConsumeInt(size_t bytes);

  // Consumes an unsigned integer of the specified size.
  py::int_ ConsumeUInt(size_t bytes);

  // Consumes an integer in the range [min, max].
  py::int_ ConsumeIntInRange(py::int_ min, py::int_ max);

  // Consumes a list of integers of the specified size.
  py::list ConsumeIntList(size_t count, size_t bytes);

  // Consumes a list of integers between the specified min and max.
  py::list ConsumeIntListInRange(size_t len, py::int_ min, py::int_ max);

  // Consume an arbitrary floating-point value.
  double ConsumeFloat();

  // Consume an arbitrary float, but never a special type (e.g. NaN, inf, etc.);
  // only real numbers.
  double ConsumeRegularFloat();

  // Consume a float in the range [0, 1].
  double ConsumeProbability();

  // Consume a float in the specified range.
  double ConsumeFloatInRange(double min, double max);

  // Consume a list of floats.
  py::list ConsumeFloatList(size_t count);

  // Consume a list of floats that are not special type (e.g. NaN, inf, etc.)
  py::list ConsumeRegularFloatList(size_t count);

  // Consume a list of floats in the range [0, 1].
  py::list ConsumeProbabilityList(size_t count);

  // Consume a list of floats in the specified range.
  py::list ConsumeFloatListInRange(size_t count, double min, double max);

  // Given a list, consume and return a value.
  py::object PickValueInList(py::list list);

  // Consume either True or False.
  bool ConsumeBool();

  // Returns the number of bytes remaining in the buffer.
  size_t remaining_bytes() { return remaining_bytes_; }

  // Returns the entire remaining buffer.
  py::bytes buffer() {
    return py::bytes(reinterpret_cast<const char *>(data_ptr_),
                     remaining_bytes_);
  }

 private:
  py::object ConsumeUnicodeImpl(size_t count, bool filter_surrogates);

  int64_t ConsumeSmallIntInRange(size_t n, uint64_t range);

  double ConsumeFloatInRangeImpl(double min, double max, int64_t value);

  void Advance(size_t bytes);

  const uint8_t *data_ptr_;
  size_t remaining_bytes_;
  // Used to ensure data_ptr_ is not deallocated.
  py::bytes ref_;
};

}  // namespace atheris

#endif  // THIRD_PARTY_PY_ATHERIS_FUZZED_DATA_PROVIDER_H_

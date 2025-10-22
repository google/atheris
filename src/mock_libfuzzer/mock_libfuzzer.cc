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

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "mock_libfuzzer_lib.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace atheris {

namespace py = pybind11;

py::object py_mock_LLVMFuzzerRunDriver = py::none();
py::object py_mock_LLVMFuzzerMutate = py::none();
py::object py_mock_sanitizer_cov_8bit_counters_init = py::none();
py::object py_mock_sanitizer_cov_pcs_init = py::none();
py::object py_mock_sanitizer_cov_trace_const_cmp8 = py::none();
py::object py_mock_sanitizer_cov_trace_cmp8 = py::none();
py::object py_mock_sanitizer_weak_hook_memcmp = py::none();

int call_py_mock_LLVMFuzzerRunDriver(int* argc, char*** argv,
                                     int (*UserCb)(const uint8_t* Data,
                                                   size_t Size)) {
  py::list argv_list;
  for (int i = 0; i < *argc; i++) {
    argv_list.append(py::str((*argv)[i]));
  }

  py::cpp_function py_user_cb = [&](py::bytes data) {
    std::string s = std::string(data);
    const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(s.data());
    size_t size = s.size();
    return UserCb(data_ptr, size);
  };

  return py_mock_LLVMFuzzerRunDriver(argv_list, py_user_cb).cast<int>();
}

void call_py_mock_sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2) {
  py_mock_sanitizer_cov_trace_const_cmp8(arg1, arg2);
}
void call_py_mock_sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2) {
  py_mock_sanitizer_cov_trace_cmp8(arg1, arg2);
}
void call_py_mock_sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                             const void* s2, size_t n,
                                             int result) {
  py::bytes s1_bytes(static_cast<const char*>(s1), n);
  py::bytes s2_bytes(static_cast<const char*>(s2), n);
  py_mock_sanitizer_weak_hook_memcmp(reinterpret_cast<uintptr_t>(caller_pc),
                                     s1_bytes, s2_bytes, n, result);
}

void set_mock_LLVMFuzzerRunDriver(py::object mock_fn) {
  py_mock_LLVMFuzzerRunDriver = mock_fn;
  if (mock_fn == py::none()) {
    mock_LLVMFuzzerRunDriver = &default_LLVMFuzzerRunDriver;
  } else {
    mock_LLVMFuzzerRunDriver = &call_py_mock_LLVMFuzzerRunDriver;
  }
}

void set_mock_sanitizer_cov_trace_const_cmp8(py::object mock_fn) {
  py_mock_sanitizer_cov_trace_const_cmp8 = mock_fn;
  if (mock_fn == py::none()) {
    mock_sanitizer_cov_trace_const_cmp8 =
        &default_sanitizer_cov_trace_const_cmp8;
  } else {
    mock_sanitizer_cov_trace_const_cmp8 =
        &call_py_mock_sanitizer_cov_trace_const_cmp8;
  }
}
void set_mock_sanitizer_cov_trace_cmp8(py::object mock_fn) {
  py_mock_sanitizer_cov_trace_cmp8 = mock_fn;
  if (mock_fn == py::none()) {
    mock_sanitizer_cov_trace_cmp8 = &default_sanitizer_cov_trace_cmp8;
  } else {
    mock_sanitizer_cov_trace_cmp8 = &call_py_mock_sanitizer_cov_trace_cmp8;
  }
}
void set_mock_sanitizer_weak_hook_memcmp(py::object mock_fn) {
  py_mock_sanitizer_weak_hook_memcmp = mock_fn;
  if (mock_fn == py::none()) {
    mock_sanitizer_weak_hook_memcmp = &default_sanitizer_weak_hook_memcmp;
  } else {
    mock_sanitizer_weak_hook_memcmp = &call_py_mock_sanitizer_weak_hook_memcmp;
  }
}

py::object get_mock_sanitizer_cov_trace_const_cmp8() {
  return py_mock_sanitizer_cov_trace_const_cmp8;
}
py::object get_mock_sanitizer_cov_trace_cmp8() {
  return py_mock_sanitizer_cov_trace_cmp8;
}
py::object get_mock_sanitizer_weak_hook_memcmp() {
  return py_mock_sanitizer_weak_hook_memcmp;
}

struct CounterEntry {
  uint8_t* start;
  uint8_t* stop;
};

struct CounterArrayData {
  size_t total_values = 0;
  std::vector<CounterEntry> values;

  py::list to_list() const {
    py::list result;
    for (const CounterEntry& entry : values) {
      uint8_t* ptr = entry.start;
      while (ptr < entry.stop) {
        result.append(py::int_(*ptr));
        ++ptr;
      }
    }
    return result;
  }

  void clear() const {
    for (const CounterEntry& entry : values) {
      memset(entry.start, 0, entry.stop - entry.start);
    }
  }
};

CounterArrayData& eightbit_counters() {
  static CounterArrayData* eightbit_counters = new CounterArrayData;
  return *eightbit_counters;
}
CounterArrayData& pcs() {
  static CounterArrayData* pcs = new CounterArrayData;
  return *pcs;
}

void pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end) {
  pcs().total_values += (pcs_end - pcs_beg);
  pcs().values.push_back({pcs_beg, pcs_end});
}
void eightbit_counters_init(uint8_t* start, uint8_t* stop) {
  eightbit_counters().total_values += (stop - start);
  eightbit_counters().values.push_back({start, stop});
}

py::list get_8bit_counters() { return eightbit_counters().to_list(); }
py::list get_pcs() { return pcs().to_list(); }
void clear_8bit_counters() { eightbit_counters().clear(); }
void clear_pcs() { pcs().clear(); }

PYBIND11_MODULE(mock_libfuzzer, m) {
  m.def("set_mock_LLVMFuzzerRunDriver", &set_mock_LLVMFuzzerRunDriver);

  m.def("get_8bit_counters", &get_8bit_counters);
  m.def("get_pcs", &get_pcs);
  m.def("clear_8bit_counters", &clear_8bit_counters);

  m.def("set_mock_sanitizer_cov_trace_const_cmp8",
        &set_mock_sanitizer_cov_trace_const_cmp8);
  m.def("set_mock_sanitizer_cov_trace_cmp8",
        &set_mock_sanitizer_cov_trace_cmp8);
  m.def("set_mock_sanitizer_weak_hook_memcmp",
        &set_mock_sanitizer_weak_hook_memcmp);

  m.def("get_mock_sanitizer_cov_trace_const_cmp8",
        &get_mock_sanitizer_cov_trace_const_cmp8);
  m.def("get_mock_sanitizer_cov_trace_cmp8",
        &get_mock_sanitizer_cov_trace_cmp8);
  m.def("get_mock_sanitizer_weak_hook_memcmp",
        &get_mock_sanitizer_weak_hook_memcmp);

  mock_sanitizer_cov_8bit_counters_init = &eightbit_counters_init;
  mock_sanitizer_cov_pcs_init = &pcs_init;
}

}  // namespace atheris

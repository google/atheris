// Copyright 2020 Google LLC
// Copyright 2021 Fraunhofer FKIE
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

#include "atheris.h"

#include <Python.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

#include <exception>
#include <iostream>
#include <limits>
#include <sstream>

#include "atheris.h"
#include "fuzzed_data_provider.h"
#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "util.h"

namespace atheris {

namespace {

std::function<void(py::bytes data)>& test_one_input_global =
    *new std::function<void(py::bytes data)>([](py::bytes data) -> void {
      std::cerr << "You must call Setup() before Fuzz()." << std::endl;
      _exit(-1);
    });

std::vector<std::string>& args_global = *new std::vector<std::string>();
uint64_t num_counters = 0;

enum internal_libfuzzer_mode {
  INTERNAL_LIBFUZZER_AUTO = 0,
  INTERNAL_LIBFUZZER_ENABLE = 1,
  INTERNAL_LIBFUZZER_DISABLE = 2
};

internal_libfuzzer_mode internal_libfuzzer = INTERNAL_LIBFUZZER_AUTO;
bool setup_called = false;

}  // namespace

// These versions of _trace_branch, _trace_cmp, and _reserve_counters are called
// before fuzzing has begun.

NO_SANITIZE
void prefuzz_trace_branch(uint64_t idx) {
  // We don't care about tracing before fuzzing starts, do nothing.
}

NO_SANITIZE
py::handle prefuzz_trace_cmp(py::handle left, py::handle right, int opid,
                             uint64_t idx, bool left_is_const) {
  // We don't care about tracing before fuzzing starts, but _trace_cmp actually
  // *replaces* the comparison, so just do a compare.
  PyObject* ret = PyObject_RichCompare(left.ptr(), right.ptr(), opid);

  if (ret == nullptr) {
    throw py::error_already_set();
  } else {
    return ret;
  }
}

NO_SANITIZE
void prefuzz_reserve_counters(uint64_t num) { num_counters += num; }

NO_SANITIZE
std::vector<std::string> Setup(
    const std::vector<std::string>& args,
    const std::function<void(py::bytes data)>& test_one_input,
    py::kwargs kwargs) {
  if (setup_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Setup() must not be called more than once.")
              << std::endl;
    exit(1);
  }
  setup_called = true;

  args_global = args;
  test_one_input_global = test_one_input;

  // Strip libFuzzer arguments (single dash).
  std::vector<std::string> ret;
  for (const std::string& arg : args) {
    if (arg.size() > 1 && arg[0] == '-' && arg[1] != '-') {
      continue;
    }
    ret.push_back(arg);
  }

  if (kwargs.contains("internal_libfuzzer")) {
    bool use_internal = kwargs["internal_libfuzzer"].cast<bool>();
    if (use_internal) {
      internal_libfuzzer = INTERNAL_LIBFUZZER_ENABLE;
    } else {
      internal_libfuzzer = INTERNAL_LIBFUZZER_DISABLE;
    }
  }

  return ret;
}

// Checks if libfuzzer is already present.
NO_SANITIZE
bool libfuzzer_is_loaded() {
  void* self_lib = dlopen(nullptr, RTLD_LAZY);
  if (!self_lib) return false;

  void* sym = dlsym(self_lib, "LLVMFuzzerRunDriver");

  dlclose(self_lib);
  return sym;
}

NO_SANITIZE
py::module LoadCoreModule() {
  if (internal_libfuzzer == INTERNAL_LIBFUZZER_AUTO) {
    // Automatically determine whether we have libfuzzer loaded
    if (libfuzzer_is_loaded()) {
      internal_libfuzzer = INTERNAL_LIBFUZZER_DISABLE;  // Don't use our own
    } else {
      internal_libfuzzer = INTERNAL_LIBFUZZER_ENABLE;  // Use our own
    }
  }

  if (internal_libfuzzer == INTERNAL_LIBFUZZER_ENABLE) {
    std::cerr << "INFO: Using built-in libfuzzer" << std::endl;
    return py::module::import("atheris.core_with_libfuzzer");
  } else {
    std::cerr << "INFO: Using preloaded libfuzzer" << std::endl;
    return py::module::import("atheris.core_without_libfuzzer");
  }
}

NO_SANITIZE
void Fuzz() {
  if (!setup_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Setup() must be called before Fuzz() can be called.")
              << std::endl;
    exit(1);
  }

  py::module atheris =
      (py::module)py::module::import("sys").attr("modules")["atheris"];
  py::module core = LoadCoreModule();

  atheris.attr("_trace_cmp") = core.attr("_trace_cmp");
  atheris.attr("_trace_branch") = core.attr("_trace_branch");
  atheris.attr("_reserve_counters") = core.attr("_reserve_counters");

  core.attr("start_fuzzing")(args_global, test_one_input_global, num_counters);
}

PYBIND11_MODULE(native, m) {
  m.def("Setup", &Setup);
  m.def("Fuzz", &Fuzz);
  m.def("_trace_branch", &prefuzz_trace_branch);
  m.def("_trace_cmp", &prefuzz_trace_cmp, py::return_value_policy::move);
  m.def("_reserve_counters", &prefuzz_reserve_counters);
  m.def("libfuzzer_is_loaded", &libfuzzer_is_loaded);

  py::class_<FuzzedDataProvider>(m, "FuzzedDataProvider")
      .def(py::init<py::bytes>())
      .def("ConsumeUnicode", &FuzzedDataProvider::ConsumeUnicode,
           py::arg("count"))
      .def("ConsumeUnicodeNoSurrogates",
           &FuzzedDataProvider::ConsumeUnicodeNoSurrogates)
      .def("ConsumeBytes", &FuzzedDataProvider::ConsumeBytes)
      .def("ConsumeString", &FuzzedDataProvider::ConsumeString)
      .def("ConsumeInt", &FuzzedDataProvider::ConsumeInt)
      .def("ConsumeUInt", &FuzzedDataProvider::ConsumeUInt)
      .def("ConsumeIntInRange", &FuzzedDataProvider::ConsumeIntInRange)
      .def("ConsumeIntList", &FuzzedDataProvider::ConsumeIntList)
      .def("ConsumeIntListInRange", &FuzzedDataProvider::ConsumeIntListInRange)
      .def("ConsumeFloat", &FuzzedDataProvider::ConsumeFloat)
      .def("ConsumeRegularFloat", &FuzzedDataProvider::ConsumeRegularFloat)
      .def("ConsumeProbability", &FuzzedDataProvider::ConsumeProbability)
      .def("ConsumeFloatInRange", &FuzzedDataProvider::ConsumeFloatInRange)
      .def("ConsumeFloatList", &FuzzedDataProvider::ConsumeFloatList)
      .def("ConsumeRegularFloatList",
           &FuzzedDataProvider::ConsumeRegularFloatList)
      .def("ConsumeProbabilityList",
           &FuzzedDataProvider::ConsumeProbabilityList)
      .def("ConsumeFloatListInRange",
           &FuzzedDataProvider::ConsumeFloatListInRange)
      .def("PickValueInList", &FuzzedDataProvider::PickValueInList)
      .def("ConsumeBool", &FuzzedDataProvider::ConsumeBool)
      .def("remaining_bytes", &FuzzedDataProvider::remaining_bytes)
      .def("buffer", &FuzzedDataProvider::buffer);
  m.attr("ALL_REMAINING") = std::numeric_limits<size_t>::max();
}

}  // namespace atheris

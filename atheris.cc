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

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

#include <Python.h>
#include <exception>
#include <iostream>
#include <sstream>
#include <limits>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "util.h"
#include "atheris.h"

namespace atheris {
    
namespace py = pybind11;

namespace {

std::function<void(py::bytes data)>& test_one_input_global =
    *new std::function<void(py::bytes data)>([](py::bytes data) -> void {
      std::cerr << "You must call Setup() before Fuzz()." << std::endl;
      _exit(-1);
    });

std::vector<std::string>& args_global = *new std::vector<std::string>();
unsigned long long num_counters = 0;
bool internal_libfuzzer = true;
bool setup_called = false;

}  // namespace

NO_SANITIZE
void _trace_branch(unsigned long long idx) {
  
}

NO_SANITIZE
void _reserve_counters(unsigned long long num) {
  num_counters += num;
}

NO_SANITIZE
py::handle _trace_cmp(py::handle left, py::handle right, int opid, unsigned long long idx, bool left_is_const) {
  PyObject* ret = PyObject_RichCompare(left.ptr(), right.ptr(), opid);
  
  if (ret == nullptr) {
    throw py::error_already_set();
  } else {
    return ret;
  }
}

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
    internal_libfuzzer = kwargs["internal_libfuzzer"].cast<bool>();
  }

  return ret;
}

NO_SANITIZE
void Fuzz() {
  if (!setup_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Setup() must be called before Fuzz() can be called.")
              << std::endl;
    exit(1);
  }

  py::module atheris = (py::module) py::module::import("sys").attr("modules")["atheris"];
  py::module core;
  
  if (internal_libfuzzer) {
    core = py::module::import("atheris.core_with_libfuzzer");
  } else {
    core = py::module::import("atheris.core_without_libfuzzer");
  }
  
  atheris.attr("_trace_cmp") = core.attr("_trace_cmp");
  atheris.attr("_reserve_counters") = core.attr("_reserve_counters");
  atheris.attr("_trace_branch") = core.attr("_trace_branch");
  
  core.attr("start_fuzzing")(args_global, test_one_input_global, num_counters);
}

#ifndef ATHERIS_MODULE_NAME
#error Need ATHERIS_MODULE_NAME
#endif  // ATHERIS_MODULE_NAME

PYBIND11_MODULE(ATHERIS_MODULE_NAME, m) {
  m.def("Setup", &Setup);
  m.def("Fuzz", &Fuzz);
  m.def("_trace_branch", &_trace_branch);
  m.def("_reserve_counters", &_reserve_counters);
  m.def("_trace_cmp", &_trace_cmp, py::return_value_policy::move);

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

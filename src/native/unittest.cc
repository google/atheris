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

#include <Python.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

#include <exception>
#include <iostream>
#include <limits>
#include <sstream>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "security/fuzzing/blaze/unittest_engine_no_main.h"
#include "util.h"

namespace atheris {

namespace {

std::function<void(py::bytes data)>& test_one_input_global =
    *new std::function<void(py::bytes data)>([](py::bytes data) -> void {
      std::cerr << "You must call Setup() before Fuzz()." << std::endl;
      _exit(-1);
    });

std::vector<std::string>& args_global = *new std::vector<std::string>();
bool setup_called = false;

}  // namespace

NO_SANITIZE
void _trace_branch(uint64_t idx) {}

NO_SANITIZE
py::handle _trace_cmp(py::handle left, py::handle right, int opid, uint64_t idx,
                      bool left_is_const) {
  PyObject* ret = PyObject_RichCompare(left.ptr(), right.ptr(), opid);

  if (ret == nullptr) {
    throw py::error_already_set();
  } else {
    return ret;
  }
}

NO_SANITIZE
void _trace_regex_match(py::handle pattern_match, py::handle object) {}


int global_counter = 0;

NO_SANITIZE
int _reserve_counter() { return global_counter++; }

std::vector<std::string> Setup(
    const std::vector<std::string>& args,
    const std::function<void(pybind11::bytes data)>& test_one_input,
    pybind11::kwargs kwargs) {
  if (setup_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Setup() must not be called more than once.")
              << std::endl;
    exit(1);
  }
  setup_called = true;

  args_global = args;
  test_one_input_global = test_one_input;
  return args;
}

int TestOneInput(const uint8_t* data, size_t size) {
  std::string input(reinterpret_cast<const char*>(data), size);
  try {
    test_one_input_global(input);
    return 0;
  } catch (py::error_already_set& ex) {
    std::cout << Colorize(STDOUT_FILENO,
                          "\n === Uncaught Python exception: ===\n");
    PrintPythonException(ex, std::cout);
    exit(-1);
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

  std::vector<char*> args;
  args.reserve(args_global.size() + 1);
  for (const std::string& arg : args_global) {
    args.push_back(const_cast<char*>(arg.c_str()));
  }
  args.push_back(nullptr);
  char** args_ptr = &args[0];
  int args_size = args_global.size();

  exit(UnittestFuzz(args_size, args_ptr, &TestOneInput));
}

NO_SANITIZE
py::bytes Mutate(py::bytes data, size_t max_size) {
  std::cerr
      << Colorize(
             STDERR_FILENO,
             "Mutate() cannot be used without libFuzzer. Without libFuzzer "
             "custom mutators are ignored, so registering them is still "
             "acceptable as long as Mutate() is only called within your custom "
             "mutator.")
      << std::endl;
  exit(1);
}

PYBIND11_MODULE(native, m) {
  m.def("Setup", &Setup);
  m.def("Fuzz", &Fuzz);
  m.def("Mutate", &Mutate);
  m.def("_trace_branch", &_trace_branch);
  m.def("_trace_cmp", &_trace_cmp, py::return_value_policy::move);
  m.def("_reserve_counter", &_reserve_counter);
  m.def("_trace_regex_match", &_trace_regex_match);

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

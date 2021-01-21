// Copyright 2020 Google LLC
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

#include <limits>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "tracer.h"
#include "util.h"

namespace atheris {

#ifndef ATHERIS_MODULE_NAME
#define ATHERIS_MODULE_NAME atheris
#endif  // ATHERIS_MODULE_NAME

PYBIND11_MODULE(ATHERIS_MODULE_NAME, m) {
  Init();

  m.def("Setup", &Setup);
  m.def("Fuzz", &Fuzz);
  m.def("TraceThisThread", [](pybind11::kwargs kwargs){
      bool enable_python_opcode_coverage = true;
      if (kwargs.contains("enable_python_opcode_coverage")) {
        enable_python_opcode_coverage =
            kwargs["enable_python_opcode_coverage"].cast<bool>();
      }
      TraceThisThread(enable_python_opcode_coverage);
  });

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

  m.def("path", &GetDynamicLocation);
}

}  // namespace atheris

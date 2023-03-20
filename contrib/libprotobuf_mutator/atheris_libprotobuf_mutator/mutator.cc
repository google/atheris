/*
 * Copyright 2022 Google LLC
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

#include "src/mutator.h"

#include <Python.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

#include "port/protobuf.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "pybind11_protobuf/native_proto_caster.h"

namespace protobuf_mutator {

namespace py = pybind11;

namespace {
py::object atheris_mutate = py::none();

extern "C" size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize) {
  if (atheris_mutate.is_none()) {
    // Cache atheris.Mutate to avoid loading it over and over.
    atheris_mutate = py::module::import("atheris").attr("Mutate");
  }
  std::string mutated_data = (py::bytes)atheris_mutate(
      py::bytes(reinterpret_cast<const char*>(Data), Size), MaxSize);
  if (mutated_data.size() > MaxSize) {
    throw std::runtime_error("The mutated data cannot be larger than MaxSize.");
  }
  memcpy(Data, mutated_data.data(), mutated_data.size());
  return mutated_data.size();
}

}  // namespace

PYBIND11_MODULE(_mutator, m) {
  pybind11_protobuf::ImportNativeProtoCasters();

  m.def("CustomProtoMutator",
        [](bool binary, py::bytes data, size_t max_size, unsigned int seed,
           std::unique_ptr<protobuf::Message> message) {
          std::string data_str = data;
          size_t size = data_str.size();
          data_str.resize(max_size);
          size_t new_size = libfuzzer::CustomProtoMutator(
              binary, reinterpret_cast<uint8_t*>(data_str.data()), size,
              max_size, seed, message.get());
          return py::bytes(data_str.data(), new_size);
        });
  m.def("CustomProtoCrossOver",
        [](bool binary, py::bytes data1, py::bytes data2, size_t max_size,
           unsigned int seed, std::unique_ptr<protobuf::Message> message1,
           std::unique_ptr<protobuf::Message> message2) {
          std::string data1_str = data1;
          std::string data2_str = data2;
          std::string out;
          out.resize(max_size);
          size_t new_size = libfuzzer::CustomProtoCrossOver(
              binary, reinterpret_cast<uint8_t*>(data1_str.data()),
              data1_str.size(), reinterpret_cast<uint8_t*>(data2_str.data()),
              data2_str.size(), reinterpret_cast<uint8_t*>(out.data()),
              max_size, seed, message1.get(), message2.get());
          return py::bytes(reinterpret_cast<const char*>(out.data()), new_size);
        });
  m.def("LoadProtoInput",
        [](bool binary, py::bytes data,
           std::unique_ptr<protobuf::Message> message)
            -> std::optional<std::unique_ptr<protobuf::Message>> {
          std::string data_str = data;
          if (libfuzzer::LoadProtoInput(
                  binary, reinterpret_cast<uint8_t*>(data_str.data()),
                  data_str.size(), message.get())) {
            return message;
          }
          return std::nullopt;
        });
}

}  // namespace protobuf_mutator

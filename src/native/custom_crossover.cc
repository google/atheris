/*
 * Copyright 2021 Google LLC
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

#include "custom_crossover.h"

#include <Python.h>
#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <stdexcept>
#include <string>

#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace atheris {

namespace py = pybind11;

namespace {
std::function<py::bytes(py::bytes data1, py::bytes data2, size_t max_out_size,
                        unsigned int seed)>& custom_crossover_global =
    *new std::function<py::bytes(py::bytes data1, py::bytes data2,
                                 size_t max_out_size, unsigned int seed)>(
        [](py::bytes data1, py::bytes data2, size_t max_out_size,
           unsigned int seed) -> py::bytes {
          // This function should never be called.
          abort();
        });
}  // namespace

NO_SANITIZE
size_t custom_crossover(const uint8_t* data1, size_t size1,
                        const uint8_t* data2, size_t size2, uint8_t* out,
                        size_t max_out_size, unsigned int seed) {
  std::string new_data = custom_crossover_global(
      py::bytes(reinterpret_cast<const char*>(data1), size1),
      py::bytes(reinterpret_cast<const char*>(data2), size2), max_out_size,
      seed);
  if (new_data.size() > max_out_size) {
    throw std::runtime_error(
        "The crossover data cannot be larger than max_size.");
  }
  memcpy(out, new_data.data(), new_data.size());
  return new_data.size();
}

NO_SANITIZE
void _set_custom_crossover(
    const std::function<py::bytes(py::bytes data1, py::bytes data2,
                                  size_t max_out_size, unsigned int seed)>&
        custom_crossover_func) {
  custom_crossover_global = custom_crossover_func;
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* data1, size_t size1,
                                            const uint8_t* data2, size_t size2,
                                            uint8_t* out, size_t max_out_size,
                                            unsigned int seed) {
  return custom_crossover(data1, size1, data2, size2, out, max_out_size, seed);
}

}  // namespace atheris

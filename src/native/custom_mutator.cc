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

#include "custom_mutator.h"

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
std::function<py::bytes(py::bytes data, size_t max_size, unsigned int seed)>&
    custom_mutator_global = *new std::function<py::bytes(
        py::bytes data, size_t max_size,
        unsigned int seed)>([](py::bytes data, size_t max_size,
                               unsigned int seed) -> py::bytes {
          // This function should never be called.
          abort();
    });
}  // namespace

NO_SANITIZE
size_t custom_mutator(uint8_t* data, size_t size, size_t max_size,
                      unsigned int seed) {
  std::string new_data = custom_mutator_global(
      py::bytes(reinterpret_cast<const char*>(data), size), max_size, seed);
  if (new_data.size() > max_size) {
    throw std::runtime_error(
        "The mutated data cannot be larger than max_size.");
  }
  memcpy(data, new_data.data(), new_data.size());
  return new_data.size();
}

NO_SANITIZE
void _set_custom_mutator(
    const std::function<py::bytes(py::bytes data, size_t max_size,
                                  unsigned int seed)>& custom_mutator_func) {
  custom_mutator_global = custom_mutator_func;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  return custom_mutator(data, size, max_size, seed);
}

}  // namespace atheris

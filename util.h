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

#ifndef THIRD_PARTY_PY_ATHERIS_UTIL_H_
#define THIRD_PARTY_PY_ATHERIS_UTIL_H_

#include <exception>
#include <ostream>

#include "pybind11/pybind11.h"

namespace atheris {

namespace py = pybind11;

// If the specified file is connected to a terminal, colorize the message in
// bold red. Otherwise, just return the message.
std::string Colorize(int fileno, const std::string& message);

// Print the specified Python exception and stack trace.
void PrintPythonException(const pybind11::error_already_set& ex,
                          std::ostream& os);

// Get a string naming the type of an exception.
std::string GetExceptionType(const pybind11::error_already_set& ex);

// Get the value of an exception.
std::string GetExceptionMessage(const pybind11::error_already_set& ex);

// Returns true if 'text' starts with 'prefix'.
bool StartsWith(const char* text, const char* prefix);

// Implementation of PyUnicode_FromKindAndData that works in both 2 and 3.
py::object UnicodeFromKindAndData(int kind, const void* buffer, ssize_t size);

// Given a handle to a Python unicode object, convert it to utf-8 bytes. This is
// essentially the same as PyUnicode_AsUTF8String, but supports strings with
// surrogates.
py::bytes UnicodeToUtf8(py::handle unicode);

// Returns the path to the dynamic library defining this function.
std::string GetDynamicLocation();

namespace internal {

inline size_t CompositeHashImpl(size_t hash) { return hash; }

template <typename IntegralArg, typename... IntegralArgs>
size_t CompositeHashImpl(size_t hash, IntegralArg first, IntegralArgs... args) {
  hash ^=
      std::hash<IntegralArg>()(first) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
  return CompositeHashImpl(hash, args...);
}

}  // namespace internal

// Given a series of std::hash-able objects, returns a hash representing the
// combination. Uses the reciprocal of the golden ratio (see boost's
// hash_combine) to ensure a sufficiently random distribution.
template <typename IntegralArg, typename... IntegralArgs>
size_t CompositeHash(IntegralArg first, IntegralArgs... args) {
  return internal::CompositeHashImpl(0, first, args...);
}

}  // namespace atheris

#endif  // THIRD_PARTY_PY_ATHERIS_UTIL_H_

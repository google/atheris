#ifndef ATHERIS_CUSTOM_MUTATOR_H_
#define ATHERIS_CUSTOM_MUTATOR_H_

#include <stddef.h>
#include <stdint.h>

#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace atheris {

namespace py = pybind11;

void _set_custom_mutator(
    const std::function<py::bytes(py::bytes data, size_t max_size,
                                  unsigned int seed)>& custom_mutator_func);
}  // namespace atheris

#endif  // ATHERIS_CUSTOM_MUTATOR_H_

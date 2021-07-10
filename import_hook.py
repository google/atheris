# Copyright 2021 Fraunhofer FKIE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""atheris instruments modules at import-time.

The instrument() function temporarily installs an import hook
(AtherisMetaPathFinder) in sys.meta_path that employs a custom loader
(AtherisSourceFileLoader, AtherisSourcelessFileLoader).
"""

import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import SourceFileLoader, SourcelessFileLoader, PathFinder
from _frozen_importlib_external import SourceFileLoader, SourcelessFileLoader
from _frozen_importlib import BuiltinImporter, FrozenImporter

from .instrument_bytecode import patch_code


class AtherisMetaPathFinder(MetaPathFinder):

  def __init__(self, include_packages, exclude_modules, trace_dataflow):
    super().__init__()
    self._include_packages = include_packages
    self._exclude_modules = exclude_modules
    self._trace_dataflow = trace_dataflow

  def find_spec(self, fullname, path, target=None):
    if fullname in self._exclude_modules:
      return None

    package_name = fullname.split(".")[0]

    if (not self._include_packages or
        package_name in self._include_packages) and package_name != "atheris":
      spec = PathFinder.find_spec(fullname, path, target)

      if spec is None or spec.loader is None:
        return None

      if isinstance(spec.loader, SourceFileLoader):
        spec.loader = AtherisSourceFileLoader(spec.loader.name,
                                              spec.loader.path,
                                              self._trace_dataflow)
      elif isinstance(spec.loader, SourcelessFileLoader):
        spec.loader = AtherisSourcelessFileLoader(spec.loader.name,
                                                  spec.loader.path,
                                                  self._trace_dataflow)
      else:
        return None

      spec.loader_state = None

      print(f"INFO: Instrumenting {fullname}", file=sys.stderr)

      return spec

    else:
      return None

  def invalidate_caches(self):
    return PathFinder.invalidate_caches()


class AtherisSourceFileLoader(SourceFileLoader):

  def __init__(self, name, path, trace_dataflow):
    super().__init__(name, path)
    self._trace_dataflow = trace_dataflow

  def get_code(self, fullname):
    code = super().get_code(fullname)

    if code is None:
      return None
    else:
      return patch_code(code, self._trace_dataflow)


class AtherisSourcelessFileLoader(SourcelessFileLoader):

  def __init__(self, name, path, trace_dataflow):
    super().__init__(name, path)
    self._trace_dataflow = trace_dataflow

  def get_code(self, fullname):
    code = super().get_code(fullname)

    if code is None:
      return None
    else:
      return patch_code(code, self._trace_dataflow)


class HookManager:

  def __init__(self, include_packages, exclude_modules, trace_dataflow):
    self._include_packages = include_packages
    self._exclude_modules = exclude_modules
    self._trace_dataflow = trace_dataflow

  def __enter__(self):
    i = 0
    while i < len(sys.meta_path):
      if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
        return self
      i += 1

    i = 0
    while i < len(sys.meta_path) and sys.meta_path[i] in [
        BuiltinImporter, FrozenImporter
    ]:
      i += 1

    sys.meta_path.insert(
        i,
        AtherisMetaPathFinder(self._include_packages, self._exclude_modules,
                              self._trace_dataflow))

    return self

  def __exit__(self, *args):
    i = 0
    while i < len(sys.meta_path):
      if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
        sys.meta_path.pop(i)
      else:
        i += 1


def instrument_imports(include=[], exclude=[]):
  """
    This function temporarily installs an import hook which instruments the
    imported modules.
    `include` is a list of module names that shall be instrumented.
    `exclude` is a list of module names that shall not be instrumented.
    Note that for every module name in `include` the whole package will
    get instrumented.
    """
  include_packages = set()

  for module_name in include + exclude:
    if not isinstance(module_name, str):
      raise RuntimeError(
          "atheris.instrument_imports() expects names of modules of type <str>")
    elif not module_name:
      raise RuntimeError(
          f"atheris.instrument_imports(): You supplied an empty module name")
    elif module_name[0] == ".":
      raise RuntimeError(
          "atheris.instrument_imports(): Please specify fully qualified module names (absolute not relative)"
      )

  for module_name in include:
    if "." in module_name:
      module_name = module_name.split(".")[0]

    include_packages.add(module_name)

  return HookManager(include_packages, set(exclude), trace_dataflow=True)

# Copyright 2021 Google LLC
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
# _frozen_importlib is a special Py Interpreter library, disable import-error.
import _frozen_importlib  # type: ignore[import]
import _frozen_importlib_external  # type: ignore[import]
from importlib import abc
from importlib import machinery
import sys
import types
from typing import Set, Optional, Sequence, Type, Union, Any
from .instrument_bytecode import patch_code

_warned_experimental = False

# A list of known loaders we should silence warnings about.
SKIP_LOADERS = set([
    # Google3 loader, implemented in native code, loads other native code.
    "StaticMetaImporter",
    # Google3 loader, implemented in native code, loads other native code as
    # well as Python code.
    "ElfZipImporter",
])


# TODO(b/207008147) Mypy does not like abc.FileLoader?
def _should_skip(loader: Any) -> bool:
  """Returns whether modules loaded with this importer should be ignored."""
  if hasattr(loader, "__qualname__"):
    if loader.__qualname__ in SKIP_LOADERS:  # type: ignore[attr-defined]
      return True

  if hasattr(loader.__class__, "__qualname__"):
    if loader.__class__.__qualname__ in SKIP_LOADERS:
      return True

  return False


class AtherisMetaPathFinder(abc.MetaPathFinder):
  """Finds and loads package metapaths with Atheris loaders."""

  def __init__(self, include_packages: Set[str], exclude_modules: Set[str],
               enable_loader_override: bool, trace_dataflow: bool):
    """Finds and loads package metapaths with Atheris loaders.

    Args:
      include_packages: If not empty, an allowlist of packages to instrument.
      exclude_modules: A denylist of modules to never instrument. This has
        higher precedent than include_packages.
      enable_loader_override: Use experimental support to instrument bytecode
        loaded from custom loaders.
      trace_dataflow: Whether or not to trace dataflow.
    """
    super().__init__()
    self._include_packages = include_packages
    self._exclude_modules = exclude_modules
    self._trace_dataflow = trace_dataflow
    self._enable_loader_override = enable_loader_override

  def find_spec(
      self,
      fullname: str,
      path: Optional[Sequence[Union[bytes, str]]],
      target: Optional[types.ModuleType] = None
  ) -> Optional[machinery.ModuleSpec]:
    """Returns the module spec if any.

    Args:
      fullname: Fully qualified name of the package.
      path: Parent package's __path__
      target: When passed in, target is a module object that the finder may use
        to make a more educated guess about what spec to return.

    Returns:
      The ModuleSpec if found, not excluded, and included if any are included.
    """
    if fullname in self._exclude_modules:
      return None

    package_name = fullname.split(".")[0]

    if (not self._include_packages or
        package_name in self._include_packages) and package_name != "atheris":
      # Try each importer after the Atheris importer until we find an acceptable
      # one
      found_atheris = False
      for meta in sys.meta_path:
        # Skip any loaders before (or including) the Atheris loader
        if not found_atheris:
          if meta is self:
            found_atheris = True
          continue

        # Check each remaining loader
        if not hasattr(meta, "find_spec"):
          continue

        spec = meta.find_spec(fullname, path, target)
        if spec is None or spec.loader is None:
          continue

        if _should_skip(spec.loader):
          return None

        if isinstance(spec.loader, machinery.ExtensionFileLoader):
          # An extension, coverage doesn't come from Python
          return None

        sys.stderr.write(f"INFO: Instrumenting {fullname}\n")

        # Use normal inheritance for the common cases. This may not be needed
        # (the dynamic case should work for everything), but keep this for as
        # long as that's experimental.
        if isinstance(spec.loader, _frozen_importlib_external.SourceFileLoader):
          spec.loader = AtherisSourceFileLoader(spec.loader.name,
                                                spec.loader.path,
                                                self._trace_dataflow)
          return spec

        elif isinstance(spec.loader,
                        _frozen_importlib_external.SourcelessFileLoader):
          spec.loader = AtherisSourcelessFileLoader(spec.loader.name,
                                                    spec.loader.path,
                                                    self._trace_dataflow)
          return spec

        else:
          # The common case isn't what we have, so wrap an existing object
          # via composition.

          if not self._enable_loader_override:
            sys.stderr.write("WARNING: Skipping import with custom loader.\n")
            return None

          global _warned_experimental
          if not _warned_experimental:
            sys.stderr.write(
                "WARNING: It looks like this module is imported by a "
                "custom loader. Atheris has experimental support for this. "
                "However, it may be incompatible with certain libraries. "
                "If you experience unusual errors or poor coverage "
                "collection, try atheris.instrument_all() instead, add "
                "enable_loader_override=False to instrument_imports(), or "
                "file an issue on GitHub.\n")
            _warned_experimental = True

          try:
            spec.loader = make_dynamic_atheris_loader(spec.loader,
                                                      self._trace_dataflow)
            return spec
          except Exception:  # pylint: disable=broad-except
            sys.stderr.write("WARNING: This module uses a custom loader that "
                             "prevents it from being instrumented: "
                             f"{spec.loader}\n")
            return None

          return None
      return None
    return None

  def invalidate_caches(self) -> None:
    return machinery.PathFinder.invalidate_caches()


class AtherisSourceFileLoader(_frozen_importlib_external.SourceFileLoader):
  """Loads a source file, patching its bytecode with Atheris instrumentation."""

  def __init__(self, name: str, path: str, trace_dataflow: bool):
    super().__init__(name, path)
    self._trace_dataflow = trace_dataflow

  def get_code(self, fullname: str) -> Optional[types.CodeType]:
    code = super().get_code(fullname)

    if code is None:
      return None
    else:
      return patch_code(code, self._trace_dataflow)


class AtherisSourcelessFileLoader(
    _frozen_importlib_external.SourcelessFileLoader):
  """Loads a sourceless/bytecode file, patching it with Atheris instrumentation."""

  def __init__(self, name: str, path: str, trace_dataflow: bool):
    super().__init__(name, path)
    self._trace_dataflow = trace_dataflow

  def get_code(self, fullname: str) -> Optional[types.CodeType]:
    code = super().get_code(fullname)

    if code is None:
      return None
    else:
      return patch_code(code, self._trace_dataflow)


def make_dynamic_atheris_loader(loader: Any, trace_dataflow: bool) -> Any:
  """Create a loader via 'object inheritance' and return it.

  This technique allows us to override just the get_code function on an
  already-existing object loader. This is experimental.

  Args:
    loader: Loader or Loader class.
    trace_dataflow: Whether or not to trace dataflow.

  Returns:
    The loader class overriden with Atheris tracing.
  """
  if loader.__class__ is type:
    # This is a class with classmethods. Use regular inheritance to override
    # get_code.

    class DynAtherisLoaderClass(loader):  # type: ignore[valid-type, misc]

      @classmethod
      def get_code(cls, fullname: str) -> Optional[types.CodeType]:
        code = loader.get_code(fullname)

        if code is None:
          return None
        return patch_code(code, cls._trace_dataflow)

    return DynAtherisLoaderClass

  # This is an object. We create a new object that's a copy of the existing
  # object but with a custom get_code implementation.
  class DynAtherisLoaderObject(loader.__class__):  # type: ignore[name-defined]
    """Dynamic wrapper over a loader."""

    def __init__(self, trace_dataflow: bool):
      self._trace_dataflow = trace_dataflow

    def get_code(self, fullname: str) -> Optional[types.CodeType]:
      code = super().get_code(fullname)

      if code is None:
        return None
      return patch_code(code, self._trace_dataflow)

  ret = DynAtherisLoaderObject(trace_dataflow)
  for k, v in loader.__dict__.items():
    if k not in ret.__dict__:
      ret.__dict__[k] = v

  return ret


class HookManager:
  """A Context manager that manages hooks."""

  def __init__(self, include_packages: Set[str], exclude_modules: Set[str],
               enable_loader_override: bool, trace_dataflow: bool):
    self._include_packages = include_packages
    self._exclude_modules = exclude_modules
    self._enable_loader_override = enable_loader_override
    self._trace_dataflow = trace_dataflow

  def __enter__(self) -> "HookManager":
    i = 0
    while i < len(sys.meta_path):
      if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
        return self
      i += 1

    i = 0
    while i < len(sys.meta_path) and sys.meta_path[i] in [
        _frozen_importlib.BuiltinImporter, _frozen_importlib.FrozenImporter
    ]:
      i += 1

    sys.meta_path.insert(
        i,
        AtherisMetaPathFinder(self._include_packages, self._exclude_modules,
                              self._enable_loader_override,
                              self._trace_dataflow))

    return self

  def __exit__(self, *args: Any) -> None:
    i = 0
    while i < len(sys.meta_path):
      if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
        sys.meta_path.pop(i)
      else:
        i += 1


def instrument_imports(include: Optional[Sequence[str]] = None,
                       exclude: Optional[Sequence[str]] = None,
                       enable_loader_override: bool = True) -> HookManager:
  """Returns a context manager that will instrument modules as imported.

  Args:
    include: module names that shall be instrumented. Submodules within these
      packages will be recursively instrumented too.
    exclude: module names that shall not be instrumented.
    enable_loader_override: Whether or not to enable the experimental feature of
      instrumenting custom loaders.

  Returns:

  Raises:
    TypeError: If any module name is not a str.
    ValueError: If any module name is a relative path or empty.
  """
  include = [] if include is None else list(include)
  exclude = [] if exclude is None else list(exclude)

  include_packages = set()

  for module_name in include + exclude:
    if not isinstance(module_name, str):
      raise TypeError("atheris.instrument_imports() expects names of " +
                      "modules of type <str>")
    elif not module_name:
      raise ValueError("atheris.instrument_imports(): " +
                       "You supplied an empty module name")
    elif module_name[0] == ".":
      raise ValueError("atheris.instrument_imports(): Please specify fully " +
                       "qualified module names (absolute not relative)")

  for module_name in include:
    if "." in module_name:
      module_name = module_name.split(".")[0]

    include_packages.add(module_name)

  return HookManager(
      include_packages,
      set(exclude),
      enable_loader_override,
      trace_dataflow=True)

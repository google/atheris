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

"""
atheris instruments modules at import-time.
The instrument() function temporarily installs an import hook (AtherisMetaPathFinder)
in sys.meta_path that employs a custom loader 
(AtherisSourceFileLoader, AtherisSourcelessFileLoader).
"""

import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import SourceFileLoader, SourcelessFileLoader, PathFinder
from _frozen_importlib_external import SourceFileLoader, SourcelessFileLoader
from _frozen_importlib import BuiltinImporter, FrozenImporter

from .instrument_bytecode import patch_code

class AtherisMetaPathFinder(MetaPathFinder):
    def __init__(self, packages, trace_dataflow):
        super().__init__()
        self._target_packages = packages
        self._trace_dataflow = trace_dataflow
    
    def find_spec(self, fullname, path, target=None):
        package_name = fullname.split(".")[0]
        
        if (not self._target_packages or package_name in self._target_packages) and package_name != "atheris":
            spec = PathFinder.find_spec(fullname, path, target)
            
            if spec is None or spec.loader is None:
                return None
            
            if isinstance(spec.loader, SourceFileLoader):
                spec.loader = AtherisSourceFileLoader(spec.loader.name, spec.loader.path, self._trace_dataflow)
            elif isinstance(spec.loader, SourcelessFileLoader):
                spec.loader = AtherisSourcelessFileLoader(spec.loader.name, spec.loader.path, self._trace_dataflow)
            else:
                return None
            
            spec.loader_state = None
            
            print(f"INFO: Instrumenting {fullname}")
            
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
    def __init__(self, packages, trace_dataflow):
        self._target_packages = packages
        self._trace_dataflow = trace_dataflow
    
    def __enter__(self):
        i = 0
        while i < len(sys.meta_path):
            if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
                return self
            i += 1
        
        i = 0
        while i < len(sys.meta_path) and sys.meta_path[i] in [BuiltinImporter, FrozenImporter]:
            i += 1
        
        sys.meta_path.insert(i, AtherisMetaPathFinder(self._target_packages, self._trace_dataflow))
        
        return self
        
    def __exit__(self, *args):
        i = 0
        while i < len(sys.meta_path):
            if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
                sys.meta_path.pop(i)
            else:
                i += 1

def instrument(*modules, trace_dataflow=True):
    """
    This function temporarily installs an import hook which instruments
    all imported modules.
    The arguments to this function are names of modules or packages.
    If it is a fully qualified module name, the name of its package will be used.
    """
    target_packages = set()
    
    for module_name in modules:
        if not isinstance(module_name, str):
            raise RuntimeError("atheris.instrument() expects names of modules of type <str>")
        elif not module_name:
            raise RuntimeError(f"atheris.instrument(): Invalid module name: {module_name}")
        elif module_name[0] == ".":
            raise RuntimeError("atheris.instrument(): Please specify fully qualified module names (absolute not relative)")
        
        if "." in module_name:
            module_name = module_name.split(".")[0]
    
        target_packages.add(module_name)
    
    return HookManager(target_packages, trace_dataflow)

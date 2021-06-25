"""
atheris instruments modules at import-time.
The Instrument() function temporarily installs an import hook (AtherisMetaPathFinder)
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
    def __init__(self, packages):
        super().__init__()
        self._target_packages = packages
    
    def find_spec(self, fullname, path, target=None):
        package_name = fullname.split(".")[0]
        
        if not self._target_packages or package_name in self._target_packages:
            spec = PathFinder.find_spec(fullname, path, target)
            
            if spec is None or spec.loader is None:
                return None
            
            if isinstance(spec.loader, SourceFileLoader):
                spec.loader = AtherisSourceFileLoader(spec.loader.name, spec.loader.path)
            elif isinstance(spec.loader, SourcelessFileLoader):
                spec.loader = AtherisSourcelessFileLoader(spec.loader.name, spec.loader.path)
            else:
                return None
            
            spec.loader_state = None
            
            print(f"Instrumenting {fullname}")
            
            return spec
        
        else:
            return None
    
    def invalidate_caches(self):
        return PathFinder.invalidate_caches()
    
class AtherisSourceFileLoader(SourceFileLoader):
    def get_code(self, fullname):
        code = super().get_code(fullname)
        
        if code is None:
            return None
        else:
            return patch_code(code, True)
    
class AtherisSourcelessFileLoader(SourcelessFileLoader):
    def get_code(self, fullname):
        code = super().get_code(fullname)
        
        if code is None:
            return None
        else:
            return patch_code(code, True)

class HookManager:
    def __init__(self, packages):
        self._target_packages = packages
    
    def __enter__(self):
        i = 0
        while i < len(sys.meta_path):
            if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
                return self
            i += 1
        
        i = 0
        while i < len(sys.meta_path) and sys.meta_path[i] in [BuiltinImporter, FrozenImporter]:
            i += 1
        
        sys.meta_path.insert(i, AtherisMetaPathFinder(self._target_packages))
        
        return self
        
    def __exit__(self, *args):
        i = 0
        while i < len(sys.meta_path):
            if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
                sys.meta_path.pop(i)
            else:
                i += 1

def instrument(*modules):
    """
    This function temporarily installs an import hook which instruments
    all imported modules.
    The arguments to this function are names of modules or packages.
    If it is a fully qualified module name, the name of its package will be used.
    """
    target_packages = set()
    
    for module_name in modules:
        if not isinstance(module_name, str):
            raise RuntimeError("atheris.Instrument() expects names of modules of type <str>")
        elif not module_name:
            raise RuntimeError(f"atheris.Instrument(): Invalid module name: {module_name}")
        elif module_name[0] == ".":
            raise RuntimeError("atheris.Instrument(): Please specify fully qualified module names (absolute not relative)")
        
        if "." in module_name:
            module_name = module_name.split(".")[0]
    
        target_packages.add(module_name)
    
    return HookManager(target_packages)

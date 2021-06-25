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

TARGET_PACKAGES = set()

class AtherisMetaPathFinder(MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        package_name = fullname.split(".")[0]
        
        if not TARGET_PACKAGES or package_name in TARGET_PACKAGES:
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
    def __enter__(self):
        i = 0
        while i < len(sys.meta_path):
            if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
                return self
            i += 1
        
        i = 0
        while i < len(sys.meta_path) and sys.meta_path[i] in [BuiltinImporter, FrozenImporter]:
            i += 1
        
        sys.meta_path.insert(i, AtherisMetaPathFinder())
        
        return self
        
    def __exit__(self, *args):
        i = 0
        while i < len(sys.meta_path):
            if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
                sys.meta_path.pop(i)
            else:
                i += 1
        
        TARGET_PACKAGES.clear()

def instrument(*modules):
    """
    This function temporarily installs an import hook which instruments
    all imported modules.
    The arguments to this function are names of modules or packages.
    If it is a fully qualified module name, the name of its package will be used.
    """
    global TARGET_PACKAGES
    
    for module_name in modules:
        if "." in module_name:
            module_name = module_name.split(".")[0]
    
        TARGET_PACKAGES.add(module_name)
    
    return HookManager()

"""
Atheris instruments all modules that get imported after atheris.
It does so by installing an import hook into sys.meta_path.
A filter can be set by calling SetTarget() with the name of the
target module.
The hook can be unregistered by calling UnregisterImportHook()
and be manually re-registered by calling RegisterImportHook().
"""

import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import SourceFileLoader, SourcelessFileLoader, PathFinder
from _frozen_importlib_external import SourceFileLoader, SourcelessFileLoader
from _frozen_importlib import BuiltinImporter, FrozenImporter

from .instrument_bytecode import patch_code

TARGET_PACKAGES = None

class AtherisMetaPathFinder(MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        package_name = fullname.split(".")[0]
        
        if TARGET_PACKAGES is None or package_name in TARGET_PACKAGES:
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
            
            #TODO: better output ?
            print(f"Instrumenting {fullname}")
            
            return spec
        
        else:
            return None
    
    def invalidate_caches(self):
        return PathFinder.invalidate_caches()
    
class AtherisSourceFileLoader(SourceFileLoader):
    def get_code(self, fullname):
        return patch_code(super().get_code(fullname), True)
    
class AtherisSourcelessFileLoader(SourcelessFileLoader):
    def get_code(self, fullname):
        return patch_code(super().get_code(fullname), True)

def set_target_module(module_name):
    global TARGET_PACKAGES
    
    if TARGET_PACKAGES is None:
        TARGET_PACKAGES = set()
    
    if "." in module_name:
        module_name = module_name.split(".")[0]
    
    TARGET_PACKAGES.add(module_name)

def unregister_import_hook():
    i = 0
    while i < len(sys.meta_path):
        if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
            sys.meta_path.pop(i)
        else:
            i += 1

def register_import_hook():
    # Don't register twice
    i = 0
    while i < len(sys.meta_path):
        if isinstance(sys.meta_path[i], AtherisMetaPathFinder):
            return
        i += 1
    
    i = 0
    while i < len(sys.meta_path) and sys.meta_path[i] in [BuiltinImporter, FrozenImporter]:
        i += 1
    
    sys.meta_path.insert(i, AtherisMetaPathFinder())
    
# Automatically register import hook
register_import_hook()

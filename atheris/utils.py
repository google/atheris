import sys
import os

def path():
    dir, _ = os.path.split(sys.modules["atheris"].__file__)
    dir, _ = os.path.split(dir)
    return dir

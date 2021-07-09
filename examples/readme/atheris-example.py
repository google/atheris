import sys
import atheris

with atheris.instrument():
  import some_library

def TestOneInput(data):
  some_library.parse(data)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
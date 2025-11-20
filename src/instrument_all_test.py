import dis
import importlib
import sys
import types
import unittest
from unittest import mock

# Mock the native extension, since it's not available in this test.
# This needs to be done before importing atheris.
import atheris

from atheris import instrument_bytecode
from atheris import version_dependent
from atheris.mock_libfuzzer import mockutils


class InstrumentationTest(unittest.TestCase):
  """Tests instrument_all will not break Python."""

  def test_instrument_all(self):
    """Import every module in the stdlib and instrument them all."""

    for module in sys.stdlib_module_names:
      if module == "antigravity":
        # this module opens an interactive console when imported.
        continue
      if "_ios_support" in module:
        # this module is not available on all platforms.
        continue
      try:
        importlib.import_module(module)
      except (ImportError, ModuleNotFoundError):
        # Some modules might not be available or raise errors on import.
        pass
    instrument_bytecode.instrument_all()
    mockutils.UpdateCounterArrays()


if __name__ == "__main__":
  mockutils.main(verbosity=2)

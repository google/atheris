# Google3-specific __init__ file. Should import all the things in src/__init__,
# just from .src.whatever instead of just .whatever.

from .src.native import Setup, Fuzz, FuzzedDataProvider, _trace_branch, _reserve_counters, _trace_cmp, ALL_REMAINING
from .src.import_hook import instrument_imports
from .src.instrument_bytecode import patch_code, instrument_func, instrument_all
from .src.utils import path

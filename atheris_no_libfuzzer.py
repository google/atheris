"""Do not use this. It's a compatibility wrapper for old fuzzers."""

import sys

sys.stderr.write("WARNING: atheris_no_libfuzzer is no longer needed. "
                 "You can now just `import atheris`.\n")
del sys

from atheris import *

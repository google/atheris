#!/bin/bash

# Exit if a test fails.
set -e

if [ -z "$PYTHON" ]; then
  PYTHON="python3"
fi

# Set up temp dir containing atheris and cd into it.
SRC_DIR="$1"
if [ -z "$SRC_DIR" ]; then
  SRC_DIR="$( dirname ${BASH_SOURCE[0]} )"
fi
cd "$SRC_DIR"
TMP_DIR="$(mktemp -d)"
cp -r . "${TMP_DIR?}"
cd "${TMP_DIR?}"

# Set up virtual env
"$PYTHON" -m virtualenv .
source bin/activate  # After this, use `python` to get the venv, not $PYTHON
python -m pip install setuptools
python -m pip install .
(cd contrib/libprotobuf_mutator && python -m pip install .)
python -m pip install PyInstaller
python -m pip install protobuf

echo "--- Starting Python Test Suite ---"
echo "Searching recursively for files matching *_test.py"

cd src

# Find files and safely iterate over them using null terminators (-print0)
# and a 'while read' loop. This safely handles spaces in file names.
find . -name '*_test.py' -print0 | while IFS= read -r -d $'\0' file; do
    echo "=================================================="
    echo "Running test: $file"

    # Execute the Python script
    python "$file"

    # Capture the exit status of the python command
    TEST_STATUS=$?

    if [ $TEST_STATUS -ne 0 ]; then
        echo "!!! FAILED: $file returned exit code $TEST_STATUS"
        # Set the overall status to 1 (failure), but keep running other tests.
        OVERALL_STATUS=1
    else
        echo "PASSED: $file"
    fi

done

echo "=================================================="

# Final summary based on the aggregated status
echo "Test Run Complete: ALL TESTS PASSED."

rm -rf "$TMP_DIR"

exit $OVERALL_STATUS

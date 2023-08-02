#!/bin/bash

# Make sure we propagate exit codes, for kokoro.
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
source bin/activate
python -m pip install .
python -m pip install PyInstaller

cd src && python -m unittest discover . -p '*_test.py'
rm -rf "$TMP_DIR"

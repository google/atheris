#!/bin/bash

# Make sure we propegate exit codes, for kokoro.
set -e

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
python3 -m virtualenv .
source bin/activate
python -m pip install .
python -m pip install PyInstaller

cd src && python3 -m unittest discover . -p '*_test.py'
rm -rf "$TMP_DIR"

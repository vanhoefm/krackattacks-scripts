#!/bin/bash

# Start from a clean environment
rm -rf venv/

# Basic python3 virtual environment
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt

# Fix a bug in scapy that isn't fixed in the PyPI version yet. For background see
# https://github.com/secdev/scapy/commit/46fa40fde4049ad7770481f8806c59640df24059
sed -i 's/find_library("libc")/find_library("c")/g' venv/lib/python*/site-packages/scapy/arch/bpf/core.py

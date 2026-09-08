#!/usr/bin/env bash
# Quick launcher — sets system proxy, starts req-red, restores on exit.
# Run with: bash run.sh
cd "$(dirname "$0")"
python3 req_red.py "$@"

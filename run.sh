#!/usr/bin/env bash
# Start the Interceptor web UI.
# Run with: bash run.sh
cd "$(dirname "$0")"
python3 server.py "$@"

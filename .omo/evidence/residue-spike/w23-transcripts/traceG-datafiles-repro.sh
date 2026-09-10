#!/usr/bin/env bash
# W2.3 trace G: isolate the ONE artifact-owned residue row from border's pypi roundtrip (trace F).
# In fresh python:3.12-slim: pip install --no-deps aihr==0.2.2 -> list /usr/local/share/aihr ->
# pip uninstall -y aihr -> list again. Proves: RECORD data_files ARE removed; the parent dir survives empty.
set -x
pip install -q --no-deps -i https://mirrors.aliyun.com/pypi/simple/ aihr==0.2.2
find /usr/local/share/aihr -exec ls -ld {} \;
pip uninstall -y -q aihr
find /usr/local/share/aihr -exec ls -ld {} \; ; echo "exit=$? (dir listing: only orphan dir remains, no children)"

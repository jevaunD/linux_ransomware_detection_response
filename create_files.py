#!/usr/bin/env python3
"""
create_files.py

Creates a directory of realistic target files and then exits. This is
step 1 of a two-process test: run this first, let it fully settle
(well outside respond.py's detection window), THEN separately run
ransomware_sim.py to simulate the actual attack against files it
discovers on its own -- not files it created itself.

Usage:
    python3 setup_targets.py [target directory] [number of files]

If no directory is given, a fresh temp directory is created and its
path is printed. You can export it for ransomware_sim.py to pick up:

    export RANSOMWARE_TARGET_DIR=$(python3 setup_targets.py | tail -1)
"""

import os
import sys
import tempfile

DEFAULT_FILE_COUNT = 150
EXTENSIONS = [".txt", ".docx", ".jpg", ".pdf", ".csv"]


def make_target_dir(directory=None, file_count=DEFAULT_FILE_COUNT):
    d = directory or tempfile.mkdtemp(prefix="ransim_targets_")
    os.makedirs(d, exist_ok=True)
    for i in range(file_count):
        ext = EXTENSIONS[i % len(EXTENSIONS)]
        path = os.path.join(d, f"document_{i}{ext}")
        with open(path, "w") as f:
            f.write("fake content!\n" * 10)
    return d


if __name__ == "__main__":
    directory = sys.argv[1] if len(sys.argv) > 1 else None
    file_count = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_FILE_COUNT

    target_dir = make_target_dir(directory, file_count)
    print(f"[setup.py] created {file_count} target files in: {target_dir}", file=sys.stderr)
    print(f"[setup.py] wait several seconds before running ransomware_sim.py, "
          f"so this activity doesn't trigger the detector seeing that it is within the window!", file=sys.stderr)

    # Prints just the path on the final stdout line, so this composes with:
    #   export RANSOMWARE_TARGET_DIR=$(python3 setup_targets.py | tail -1)
    print(target_dir)

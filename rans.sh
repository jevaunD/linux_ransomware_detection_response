#!/usr/bin/env bash
#
# ransomware_sim.sh
#
# Bash port of ransomware_sim.py -- tests whether the detector also
# catches non-Python attacker tooling. Discovers targets via
# RANSOMWARE_TARGET_DIR (falls back to $HOME) and modifies each
# file's content in place.
#
# IMPORTANT DESIGN NOTE:
# The read (`$(<"$f")`) and the write (`> "$f"`) below use bash's OWN
# file descriptors via redirection -- no subprocess is forked for
# those, so those OPEN events are attributed to THIS script's PID
# ($$), the same way os.rename()/open() in the Python version stayed
# in one process.
#
# The final rename step, however, has no bash builtin equivalent --
# it shells out to `mv`, which forks a brand-new, short-lived process
# per file. That RENAME event lands on a DIFFERENT pid than this
# script's own OPEN events.
#
# This is a genuinely useful test case: it demonstrates that a
# per-PID aggregation detector can be blind to attacker code that
# forks a new process per file operation (very common in real
# script-based malware/loaders that shell out to openssl, mv, etc.
# per file). Expect this run to be detected mostly (or only) via the
# OPEN volume on this script's own PID -- if the OPEN weight/threshold
# alone isn't enough to cross THRESHOLD in respond.py, this run may
# slip through entirely, which is worth documenting as a discovered
# detection gap.

set -uo pipefail

TARGET_DIR="/home/jevaun/harness_dir"
LOCKED_SUFFIX=".locked"

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "[ransomware_sim.sh] target directory not found: $TARGET_DIR" >&2
    exit 1
fi

echo "[ransomware_sim.sh] pid=$$ scanning $TARGET_DIR" >&2

shopt -s globstar nullglob
file_count=0

for f in "$TARGET_DIR"/**/*; do
    [[ -f "$f" ]] || continue
    [[ "$f" == *"$LOCKED_SUFFIX" ]] && continue

    # Read via bash's own fd (command substitution's $(<file) form
    # does not fork a subprocess) -- this is a read-only open and
    # won't show up in the write-intent filtered trace, same as the
    # Python version's read step.
    content="$(<"$f")"
    content_len=${#content}

    # Trivial in-process "encryption" marker -- write back via
    # redirection, which is a write-intent open attributed to THIS
    # script's own pid ($$).
    printf 'LOCKED-%d-BYTES-%s' "$content_len" "$RANDOM" > "$f"

    # Rename to add the .locked extension. This forks a new `mv`
    # process -- see the design note above.
    mv "$f" "${f}${LOCKED_SUFFIX}" 2>/dev/null

    file_count=$((file_count + 1))
done

echo "[ransomware_sim.sh] done -- processed $file_count files" >&2

#!/usr/bin/env bash


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

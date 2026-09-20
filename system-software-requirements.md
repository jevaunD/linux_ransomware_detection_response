# Requirements — Linux Ransomware Behavior Detector (bpftrace prototype)

This document covers the environment, dependencies, and functional scope for the
bpftrace-based ransomware detection prototype (`ransomware_trace.bt`, `respond.py`,
`create_files.py`, `ransomware_sim.py`, `rans.sh`).

## System Requirements

- **OS:** Linux (kernel 4.7+ recommended for tracepoint support; 5.x+ ideal for best
  eBPF compatibility)
- **Kernel headers/BTF:** Needed for bpftrace to resolve tracepoint argument structs
  (`sys_enter_openat`, `sys_enter_renameat2`, `sys_enter_unlinkat`)
- **Root/sudo access:** Required for both bpftrace (to attach kernel probes) and the
  response layer (to signal arbitrary PIDs)

## Software Dependencies

- **bpftrace** 0.14+ recommended
  - Not installed by default on most distros — install with:
    ```bash
    # Ubuntu / Debian
    sudo apt update
    sudo apt install bpftrace

    # Fedora
    sudo dnf install bpftrace

    # Arch
    sudo pacman -S bpftrace

    # Verify installation
    bpftrace --version
    ```
  - Known issue: distro-packaged binaries are sometimes stripped of symbols, which
    breaks `BEGIN`/`END` probes with `ERROR: Could not resolve symbol:
    /proc/self/exe:BEGIN_trigger`. Fix: install `bpftrace-dbgsym`, downgrade, or (as
    done in this project) avoid `BEGIN`/`END` blocks entirely.
- **Python 3.8+**
  - Standard library only: `os`, `sys`, `time`, `signal`, `collections`, `tempfile`
  - No `pip` installs required at this stage

## Functional Requirements

### Detection (`ransomware_trace.bt` + `respond.py`)
- Trace file `open` (write-intent only), `rename`, and `delete` syscalls system-wide
- Aggregate events per-process ID within a sliding time window
- Apply weighted scoring (rename/delete weighted higher than open)
- Alert when a process's score crosses a configurable threshold within the window
- Suppress repeat alerts on the same PID via a cooldown period
- Filter out known-noisy benign processes via a `comm`-pattern denylist

### Response (`respond.py`)
- Support a dry-run mode that logs intended actions without executing them
- Refuse to act on PIDs below a configurable floor (protects core/system PIDs)
- Refuse to act on root-owned processes unless explicitly overridden
- Support both a reversible action (`SIGSTOP`) and a destructive one (`SIGKILL`),
  configurable
- Log every response decision, including skipped/refused actions, for auditability

### Testing (`setup_targets.py` + `ransomware_sim.py`)
- Target file creation must be a separate process/step from the simulated attack
- Simulated attack must discover targets dynamically (via environment variable +
  directory walk), not via hardcoded filenames
- Must support both a "malicious" (rapid, bulk) and realistic file-mix scenario for
  validating true positives without relying on a single combined harness

## Non-Functional / Design Requirements

- **Low overhead:** bpftrace-based tracing should not noticeably degrade system
  performance during normal use
- **Tunability:** window size, score threshold, weights, and denylist must be easy to
  adjust without code restructuring (currently config constants at the top of
  `respond.py`)
- **Safety-first defaults:** any destructive response action must default to
  off/dry-run; opting into real signaling should be a deliberate configuration
  change, not the default behavior
- **Portability path:** scoring/response logic should be structured so it can later
  be ported from consuming bpftrace's stdout to consuming events from a Go/Cilium
  eBPF pipeline, without rewriting the detection logic itself

## Known Gaps

- No persistent storage/logging to disk yet (all output is stdout — no historical
  record survives a restart)
- No distinct-file-diversity signal yet (a process rewriting the same file
  repeatedly scores identically to one touching many different files)
- Single-window scoring only; no longer-term behavioral baseline per process
- No test coverage for `write` syscalls directly (currently inferred only from
  `openat` flags, not from actual write volume/size)

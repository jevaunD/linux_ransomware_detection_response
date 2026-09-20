# Requirements (Linux Ransomware Detection & Response (bpftrace prototype)

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

### Response Actions

- Respond to flagged processes by sending `SIGSTOP`, which pauses the process
  without terminating it. The action is fully reversible.
- Refuse to act on PIDs below a configurable floor (`PID_FLOOR`, default 1000)
  to protect core/system processes.
- Refuse to act on its own PID, so the program can never freeze itself.
- Refuse to act on root-owned processes unless explicitly overridden
  (`ALLOW_ROOT = True`).
- Log every response decision to `actions.log`, including skipped/refused
  actions. Each entry includes a timestamp, process name, PID, and outcome
  (stopped, or skipped with the reason: protected PID, root-owned,
  permission denied, already exited).

### Recovering a Stopped Process

If a legitimate program gets paused by `respond.py`, resume it with `SIGCONT`.
It picks up exactly where it left off.

1. Find the PID and name in `actions.log`, or list paused processes
   (state `T`):

       ps -eo pid,stat,comm | awk '$2 ~ /^T/'

2. Resume it:

       kill -CONT <pid>

   Or by name:

       pkill -CONT <process_name>

### Testing (`create_files.py` + `ransomware_sim.py`)
- Target file creation must be a separate process/step from the simulated attack
- Simulated attack can discover targets dynamically (via environment variable +
  directory walk), or via hardcoded filenames
- Must support both a "malicious" (rapid, bulk) and realistic file-mix scenario for
  validating true positives without relying on a single combined harness

## Non-Functional / Design Requirements

- **Low overhead:** bpftrace-based tracing should not noticeably degrade system
  performance during normal use
- **Tunability:** window size, score threshold, weights, and denylist must be easy to
  adjust without code restructuring (currently config constants at the top of
  `respond.py`)
- **Use in a safe environment only:** `respond.py` sends real `SIGSTOP`
  signals by default, with no dry-run mode and no confirmation prompt. Run it
  only in an environment that is safe to experiment in (a VM, container, or
  test machine), not on a production or daily-driver system. Stopped processes
  can be resumed with `SIGCONT` (see *Recovering a Stopped Process*), but a
  paused legitimate program can still cause disruption in the meantime.


## Known Gaps

- No persistent storage/logging to disk yet (all output is stdout. So, no historical
  record survives a restart)
- No distinct-file-diversity signal yet (a process rewriting the same file
  repeatedly scores identically to one touching many different files)
- Single-window scoring only; no longer-term behavioral baseline per process
- No test coverage for `write` syscalls directly (currently inferred only from
  `openat` flags, not from actual write volume/size)


  - **False positives are possible.** Detection is based on behavior (rapid
  file activity), not on knowing what a program actually is, so a legit
  program that acts like ransomware can get flagged. For example, running
  `create_files.py` while the tracer is active will trigger it and freeze
  the script mid-execution. Nothing is lost, since the process is only
  paused (see *Recovering a Stopped Process*), but expect the occasional
  legit program to get caught. Run it in a safe environment, and generate
  your test files *before* starting the tracer.

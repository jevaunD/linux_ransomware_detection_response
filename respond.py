#!/usr/bin/env python3
"""

respond.py

Reads CSV event lines from bpftrace (via stdin) in the form:
    EVENT_TYPE,PID,COMM,PATH,TIMESTAMP_NS

Aggregates events per-PID over a sliding time window and raises an
alert when a process's weighted event score crosses a threshold in
that window -- the classic ransomware signature of "many file
open/rename/delete operations in rapid succession."

Usage:
    sudo bpftrace ransomware_trace.bt | python3 score.py
"""
import signal
import os
import sys
import time
from collections import defaultdict, deque

# --- Tunable parameters (start here when iterating) ---------------------
WINDOW_SECONDS = 3          # sliding window size
THRESHOLD = 50               # weighted score that triggers an alert
WEIGHTS = {                  # rename/delete are stronger ransomware signals
    "OPEN": 1,
    "RENAME": 4,
    "DELETE": 4,
}
COOLDOWN_SECONDS = 10         # don't re-alert on the same pid immediately
# --------------------------------------------------------------------

# pid -> deque of (timestamp, weight, event_type)
events_by_pid = defaultdict(deque)
# pid -> last alert time, to avoid alert spam
last_alert = {}

COMM_DENYLIST_PATTERNS = [

	"gnome-shel", "flameshot","Xorg","systemd", "system76-schedu",
	"chrome", "brave", "firefox", "Xwayland", "hostnamed", "nautilus", "MemoryInfra", "Cache2 I/O", "ThreadPoolForeg"  
]

#This gets rid of the false positives as some processes manipulate many files just as how ransomware does.
def is_denylisted(comm):
	return any(pattern in comm for pattern in COMM_DENYLIST_PATTERNS)



# --- Response / safety parameters -----------------------------------------
DRY_RUN = False                  # flip to False only once you trust this
RESPONSE_ACTION = "SIGSTOP"     # "SIGSTOP" (pause, reversible) or "SIGKILL"
MIN_TARGETABLE_PID = 1000       # refuse to touch low/system PIDs outright
ALLOW_ROOT_TARGETS = False      # refuse root-owned processes unless True
# --------------------------------------------------------------------------





def prune_and_score(pid, now):
    dq = events_by_pid[pid]
    while dq and now - dq[0][0] > WINDOW_SECONDS:
        dq.popleft()
    return sum(w for _, w, _ in dq), len(dq)


def event_breakdown(pid):
    counts = defaultdict(int)
    for _, _, etype in events_by_pid[pid]:
        counts[etype] += 1
    return dict(counts)



def get_pid_owner_uid(pid):
    """Return the UID that owns `pid`, or None if it can't be determined
    (e.g. the process has already exited)."""
    try:
        stat_path = f"/proc/{pid}"
        return os.stat(stat_path).st_uid
    except OSError:
        return None


def respond(pid, comm, score):
    """Apply the configured safety checks, then log or act."""
    if pid in responded_pids:
        return  # already handled this pid
 
    if pid < MIN_TARGETABLE_PID:
        print(f"[response-skip] pid={pid} comm={comm} below MIN_TARGETABLE_PID "
              f"({MIN_TARGETABLE_PID}) -- refusing to act", flush=True)
        return
 
    owner_uid = get_pid_owner_uid(pid)
    if owner_uid == 0 and not ALLOW_ROOT_TARGETS:
        print(f"[response-skip] pid={pid} comm={comm} is root-owned -- "
              f"refusing to act (set ALLOW_ROOT_TARGETS=True to override)",
              flush=True)
        return
 
    sig = signal.SIGSTOP if RESPONSE_ACTION == "SIGSTOP" else signal.SIGKILL
 
    if DRY_RUN:
        print(f"[response-dry-run] would send {sig.name} to pid={pid} "
              f"comm={comm} score={score}", flush=True)
        return
 
    try:
        os.kill(pid, sig)
        responded_pids.add(pid)
        print(f"[response] sent {sig.name} to pid={pid} comm={comm} "
              f"score={score}", flush=True)
    except ProcessLookupError:
        print(f"[response-fail] pid={pid} no longer exists", flush=True)
    except PermissionError:
        print(f"[response-fail] pid={pid} comm={comm}: not permitted -- "
              f"is this script running as root?", flush=True)
 





def main():
    if DRY_RUN:
        print("[respond.py] running in DRY_RUN mode -- no signals will "
              "actually be sent. Set DRY_RUN = False once you trust the "
              "detection logic in your environment.", flush=True)
 
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line or line.startswith("EVENT,PID"):
            continue
 
        parts = line.split(",", 4)
        if len(parts) != 5:
            continue
        etype, pid_s, comm, path, _nsecs_s = parts
 
        try:
            pid = int(pid_s)
        except ValueError:
            continue
 
        now = time.time()
        weight = WEIGHTS.get(etype, 1)
        events_by_pid[pid].append((now, weight, etype))
 
        score, count = prune_and_score(pid, now)
 
        if score >= THRESHOLD and not is_denylisted(comm):
            last = last_alert.get(pid, 0)
            if now - last >= COOLDOWN_SECONDS:
                last_alert[pid] = now
                breakdown = event_breakdown(pid)
                print(
                    f"[ALERT] pid={pid} comm={comm} score={score} "
                    f"events_in_window={count} breakdown={breakdown} "
                    f"last_path={path}",
                    flush=True,
                )
                respond(pid, comm, score)
 
 
if __name__ == "__main__":
    main()
 

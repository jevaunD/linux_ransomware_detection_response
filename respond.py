#!/usr/bin/env python3
"""

respond.py

Reads CSV event lines from bpftrace (via stdin) in the form:
    EVENT_TYPE,PID,COMM,PATH,TIMESTAMP_NS

Aggregates events per PID over a sliding time window (adjustable) and raises an
alert when a process's weighted event score crosses a threshold in
that window.

The classic ransomware signature of "many file
open -> rename -> delete operations in rapid succession."

Usage:
    sudo bpftrace ransomware_trace.bt | python3 score.py
"""
import signal
import os
import sys
import time
from collections import defaultdict, deque

# --- Adjustable parameters ---------------------
WINDOW_SECONDS = 5          # sliding window size
THRESHOLD = 50               # weighted score that triggers an alert
WEIGHTS = {                  # rename/delete are stronger ransomware signals
    "OPEN": 1,
    "RENAME": 4,
    "DELETE": 4,
}
COOLDOWN_SECONDS = 10         # don't send alert on the same pid immediately
# --------------------------------------------------------------------

# pid -> deque of (timestamp, weight, event_type)
events_by_pid = defaultdict(deque)
# pid -> last alert time, to avoid alert spam
last_alert = {}

COMM_DENYLIST_PATTERNS = [

	"gnome-shel", "flameshot","Xorg","systemd", "system76-schedu",
	"chrome", "brave", "firefox", "Xwayland", "hostnamed", "nautilus", "MemoryInfra", "Cache2 I/O", "ThreadPoolForeg", "CompositorTileW", "Chrome_IOThread",  
]

#This gets rid of the false positives as some processes manipulate many files just as how ransomware does.
def is_denylisted(comm):
	return any(pattern in comm for pattern in COMM_DENYLIST_PATTERNS)


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

def stop_process(pid, comm):
    try:
        os.kill(pid, signal.SIGSTOP)
        print(f"[ALERT!]\n Process: {comm}\n PID: {pid}\n Action: SIGSTOP (Process stopped!)")
        return True
    except PermissionError:
        print(f"Process: {comm}\n PID: {pid}\n Action: SKIPPED (not permitted, owned by another user or protected)")
    except ProcessLookupError:
        print(f"Process: {comm}\n PID: {pid}\n Action: SKIPPED (already exited)")
    return False


def main():

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
                stop_process(pid, comm)
               # print(
               #     f"[ALERT] pid={pid} comm={comm} score={score} "
               #     f"events_in_window={count} breakdown={breakdown} "
               #     f"last_path={path}",
               #     flush=True,
               # )
 
 
if __name__ == "__main__":
    main()
 

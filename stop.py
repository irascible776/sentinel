#!/usr/bin/env python3
"""
Sentinel AI Security Gateway — Unified Stopper & Process Cleanup Utility
Run:
    python stop.py
    ./stop.sh

Stops all active Sentinel processes and releases bound ports:
  • Gateway Server    (FastAPI / Uvicorn on port 8000)
  • Dashboard Server  (Streamlit on port 8501)
  • Stale launcher or worker processes (start.py, reloader sub-processes)
"""

import os
import sys
import time
import signal
import argparse
import subprocess
from typing import List, Dict, Set, Tuple

GATEWAY_PORT = 8000
DASHBOARD_PORT = 8501

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        SENTINEL AI Security Gateway  —  STOPPER          ║
║   Prompt Injection Detection & Prevention — Group 138    ║
╚══════════════════════════════════════════════════════════╝
"""


def get_cmdline_for_pid(pid: int) -> str:
    """Read the command line string for a given PID from /proc or ps."""
    try:
        proc_cmd = f"/proc/{pid}/cmdline"
        if os.path.exists(proc_cmd):
            with open(proc_cmd, "rb") as f:
                raw = f.read()
            parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]
            if parts:
                return " ".join(parts)
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "command="],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if out:
            return out
    except Exception:
        pass

    return f"PID {pid}"


def get_pids_on_port(port: int) -> Set[int]:
    """Find all PIDs listening or connected on a TCP port using lsof / fuser / ss."""
    pids: Set[int] = set()

    # 1. Try lsof
    try:
        out = subprocess.check_output(
            ["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if out:
            for p in out.split():
                if p.isdigit():
                    pids.add(int(p))
    except Exception:
        pass

    # Fallback to any connection on that port via lsof if listen didn't match
    if not pids:
        try:
            out = subprocess.check_output(
                ["lsof", "-t", f"-i:{port}"],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            if out:
                for p in out.split():
                    if p.isdigit():
                        pids.add(int(p))
        except Exception:
            pass

    # 2. Fallback: try fuser
    if not pids:
        try:
            out = subprocess.check_output(
                ["fuser", f"{port}/tcp"],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            if out:
                for p in out.split():
                    clean_p = "".join(ch for ch in p if ch.isdigit())
                    if clean_p:
                        pids.add(int(clean_p))
        except Exception:
            pass

    return pids


def get_pids_by_pattern(pattern: str) -> Set[int]:
    """Find PIDs whose command lines match a given pattern."""
    pids: Set[int] = set()
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", pattern],
            stderr=subprocess.DEVNULL
        ).decode().strip()
        if out:
            for p in out.split():
                if p.isdigit():
                    pids.add(int(p))
    except Exception:
        pass
    return pids


def is_pid_alive(pid: int) -> bool:
    """Check if process is currently running and accessible."""
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def kill_pids(pids: Set[int], name: str, force: bool = False, timeout: float = 3.0) -> Tuple[int, int]:
    """
    Terminates a set of PIDs politely with SIGTERM, waits up to timeout,
    and escalates to SIGKILL if necessary.
    Returns (num_stopped_gracefully, num_killed_forcefully).
    """
    my_pid = os.getpid()
    valid_pids = [p for p in pids if p != my_pid and p > 1 and is_pid_alive(p)]

    if not valid_pids:
        return (0, 0)

    stopped_graceful = 0
    killed_forced = 0

    if force:
        # Immediate SIGKILL
        for pid in valid_pids:
            try:
                os.kill(pid, signal.SIGKILL)
                killed_forced += 1
            except ProcessLookupError:
                pass
        return (0, killed_forced)

    # 1. Send SIGTERM
    print(f"  ↪ Sending SIGTERM to {name} (PIDs: {valid_pids}) …")
    for pid in valid_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    # 2. Wait up to timeout for processes to shut down
    start_time = time.time()
    still_alive = list(valid_pids)
    while still_alive and (time.time() - start_time) < timeout:
        time.sleep(0.2)
        still_alive = [p for p in still_alive if is_pid_alive(p)]

    stopped_graceful = len(valid_pids) - len(still_alive)

    # 3. Escalate to SIGKILL for any stubborn lingering process
    if still_alive:
        print(f"  ⚠️  Processes {still_alive} did not exit after {timeout}s. Escalating to SIGKILL …")
        for pid in still_alive:
            try:
                os.kill(pid, signal.SIGKILL)
                killed_forced += 1
            except ProcessLookupError:
                pass
        time.sleep(0.3)

    return (stopped_graceful, killed_forced)


def stop_sentinel(
    stop_gateway: bool = True,
    stop_dashboard: bool = True,
    force: bool = False,
    quiet: bool = False
) -> int:
    """Find and stop all Sentinel components."""
    if not quiet:
        print(BANNER)

    my_pid = os.getpid()
    gateway_pids: Set[int] = set()
    dashboard_pids: Set[int] = set()

    # ── 1. Discover Gateway processes (port 8000 & signatures) ─────────────
    if stop_gateway:
        gateway_pids.update(get_pids_on_port(GATEWAY_PORT))
        # Match uvicorn core.gateway.app:app
        gateway_pids.update(get_pids_by_pattern("core\\.gateway\\.app"))
        # Match start.py
        gateway_pids.update(get_pids_by_pattern("start\\.py"))

    # ── 2. Discover Dashboard processes (port 8501 & signatures) ───────────
    if stop_dashboard:
        dashboard_pids.update(get_pids_on_port(DASHBOARD_PORT))
        # Match streamlit dashboard/app.py
        dashboard_pids.update(get_pids_by_pattern("streamlit.*dashboard/app\\.py"))
        dashboard_pids.update(get_pids_by_pattern("dashboard/app\\.py"))

    # Filter out current process and invalid PIDs
    gateway_pids = {p for p in gateway_pids if p != my_pid and p > 1 and is_pid_alive(p)}
    dashboard_pids = {p for p in dashboard_pids if p != my_pid and p > 1 and is_pid_alive(p)}

    total_targets = len(gateway_pids | dashboard_pids)

    if total_targets == 0:
        print("ℹ️  No active Sentinel servers detected.")
        print(f"   • Port {GATEWAY_PORT} (Gateway)   : FREE")
        print(f"   • Port {DASHBOARD_PORT} (Dashboard) : FREE\n")
        return 0

    print(f"🔍 Discovered {total_targets} active process(es) to terminate:")
    if gateway_pids:
        print(f"   • Gateway Service (port {GATEWAY_PORT}):")
        for p in sorted(gateway_pids):
            cmd = get_cmdline_for_pid(p)
            print(f"       - PID {p}: {cmd[:90]}{'...' if len(cmd) > 90 else ''}")
    if dashboard_pids:
        print(f"   • Dashboard Service (port {DASHBOARD_PORT}):")
        for p in sorted(dashboard_pids):
            cmd = get_cmdline_for_pid(p)
            print(f"       - PID {p}: {cmd[:90]}{'...' if len(cmd) > 90 else ''}")
    print()

    # ── 3. Terminate components ────────────────────────────────────────────
    gw_graceful, gw_forced = 0, 0
    db_graceful, db_forced = 0, 0

    if gateway_pids:
        print(f"🛑 Stopping Gateway Server (port {GATEWAY_PORT}) …")
        gw_graceful, gw_forced = kill_pids(gateway_pids, "Gateway", force=force)

    if dashboard_pids:
        print(f"🛑 Stopping Dashboard Server (port {DASHBOARD_PORT}) …")
        db_graceful, db_forced = kill_pids(dashboard_pids, "Dashboard", force=force)

    # ── 4. Verify port status ──────────────────────────────────────────────
    time.sleep(0.2)
    gw_remaining = get_pids_on_port(GATEWAY_PORT) - {my_pid}
    db_remaining = get_pids_on_port(DASHBOARD_PORT) - {my_pid}

    print("\n" + "═" * 58)
    print("                SHUTDOWN STATUS SUMMARY")
    print("═" * 58)

    if stop_gateway:
        if not gw_remaining:
            print(f"  ✅ Gateway Server   [:{GATEWAY_PORT}] : STOPPED  (Cleaned {gw_graceful + gw_forced} process(es))")
        else:
            print(f"  ❌ Gateway Server   [:{GATEWAY_PORT}] : STILL OCCUPIED by PID(s): {list(gw_remaining)}")

    if stop_dashboard:
        if not db_remaining:
            count = db_graceful + db_forced
            status_text = f"STOPPED  (Cleaned {count} process(es))" if count > 0 else "INACTIVE / ALREADY STOPPED"
            print(f"  ✅ Dashboard Server [:{DASHBOARD_PORT}] : {status_text}")
        else:
            print(f"  ❌ Dashboard Server [:{DASHBOARD_PORT}] : STILL OCCUPIED by PID(s): {list(db_remaining)}")

    all_clean = (not gw_remaining) and (not db_remaining)
    if all_clean:
        print("\n✨ All Sentinel services stopped cleanly. Ports are released.")
    else:
        print("\n⚠️  Some processes could not be stopped. Try running: python stop.py --force")
    print("═" * 58 + "\n")

    return 0 if all_clean else 1


def main():
    parser = argparse.ArgumentParser(
        description="Gracefully stop Sentinel AI Security Gateway and Security Operations Dashboard."
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force immediate kill (SIGKILL) without waiting for graceful SIGTERM."
    )
    parser.add_argument(
        "--gateway-only",
        action="store_true",
        help="Only stop the Gateway server (port 8000)."
    )
    parser.add_argument(
        "--dashboard-only",
        action="store_true",
        help="Only stop the Dashboard server (port 8501)."
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Run quietly with minimal output."
    )

    args = parser.parse_args()

    stop_gw = not args.dashboard_only
    stop_db = not args.gateway_only

    code = stop_sentinel(
        stop_gateway=stop_gw,
        stop_dashboard=stop_db,
        force=args.force,
        quiet=args.quiet
    )
    sys.exit(code)


if __name__ == "__main__":
    main()

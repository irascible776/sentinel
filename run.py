#!/usr/bin/env python3
"""
Sentinel v2.0 Unified Local Runner
Starts both the AI Security Gateway (FastAPI on :8000) and SOC Telemetry Dashboard (Streamlit on :8501)
with a single command and unified process lifecycle management (clean SIGINT/Ctrl+C teardown).
"""

import sys
import os
import time
import socket
import signal
import subprocess
from typing import List

# Configuration Defaults
GATEWAY_HOST = os.getenv("GATEWAY_HOST", "127.0.0.1")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8000"))
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8501"))

processes: List[subprocess.Popen] = []


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks if a network port is already occupied."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def shutdown_processes(signum=None, frame=None):
    """Gracefully shuts down all child processes on Ctrl+C."""
    print("\n\n[Sentinel] Shutting down services cleanly...")
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    # Wait up to 3 seconds for clean exit, then force kill if needed
    time.sleep(1.0)
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass

    print("[Sentinel] All services terminated. Ports released.")
    sys.exit(0)


def main():
    print("=" * 70)
    print("   🛡️   SENTINEL v2.0 — AI SECURITY GATEWAY & SOC DASHBOARD")
    print("=" * 70)

    # 1. Check Port Availability
    if is_port_in_use(GATEWAY_PORT, GATEWAY_HOST):
        print(f"[ERROR] Port {GATEWAY_PORT} is already in use!")
        print(f"        Please free port {GATEWAY_PORT} before starting Sentinel Gateway.")
        sys.exit(1)

    if is_port_in_use(DASHBOARD_PORT, "127.0.0.1"):
        print(f"[ERROR] Port {DASHBOARD_PORT} is already in use!")
        print(f"        Please free port {DASHBOARD_PORT} before starting Sentinel Dashboard.")
        sys.exit(1)

    # 2. Register Signal Handlers
    signal.signal(signal.SIGINT, shutdown_processes)
    signal.signal(signal.SIGTERM, shutdown_processes)

    # 3. Launch Gateway Server (FastAPI / Uvicorn)
    print(f"\n[1/2] Launching AI Security Gateway on http://{GATEWAY_HOST}:{GATEWAY_PORT}...")
    gateway_cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "core.gateway.app:app",
        "--host",
        GATEWAY_HOST,
        "--port",
        str(GATEWAY_PORT),
    ]
    gw_proc = subprocess.Popen(gateway_cmd)
    processes.append(gw_proc)

    # Give gateway a brief moment to bind port
    time.sleep(1.5)

    # 4. Launch SOC Dashboard (Streamlit)
    print(f"[2/2] Launching SOC Telemetry Dashboard on http://127.0.0.1:{DASHBOARD_PORT}...")
    dashboard_cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "dashboard/app.py",
        "--server.port",
        str(DASHBOARD_PORT),
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]
    dash_proc = subprocess.Popen(dashboard_cmd)
    processes.append(dash_proc)

    print("\n" + "-" * 70)
    print(" ✅  SENTINEL RUNNING LOCALLY (Press Ctrl+C to Stop All Services)")
    print("-" * 70)
    print(f" • SOC Dashboard GUI:      http://127.0.0.1:{DASHBOARD_PORT}")
    print(f" • Gateway Web Chat:       http://{GATEWAY_HOST}:{GATEWAY_PORT}/")
    print(f" • Interactive API Docs:   http://{GATEWAY_HOST}:{GATEWAY_PORT}/docs")
    print(f" • Gateway Health Check:   http://{GATEWAY_HOST}:{GATEWAY_PORT}/health")
    print("-" * 70 + "\n")

    # Monitor processes
    try:
        while True:
            time.sleep(1)
            for proc in processes:
                if proc.poll() is not None:
                    print(f"\n[Sentinel Warning] A service exited with code {proc.returncode}.")
                    shutdown_processes()
    except KeyboardInterrupt:
        shutdown_processes()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Sentinel AI Security Gateway — Unified Launcher
Run:  python start.py
Opens http://127.0.0.1:8000 automatically once the gateway is ready.
"""
import os
import sys
import time
import subprocess
import threading
import webbrowser

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8000
BASE_URL     = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}"
GATEWAY_URL  = f"{BASE_URL}/sentinel"
HEALTH_URL   = f"{BASE_URL}/health"

BANNER = """
╔══════════════════════════════════════════════════════════╗
║        SENTINEL AI Security Gateway  v1.0.0              ║
║   Prompt Injection Detection & Prevention — Group 138    ║
║   DTU · B.Tech Minor Project (IT401)                     ║
╚══════════════════════════════════════════════════════════╝
"""

def check_health(timeout: int = 30) -> bool:
    """Poll /health until gateway is ready or timeout."""
    import urllib.request
    import urllib.error
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def browser_opener():
    """Background thread: waits for health, then opens browser."""
    print("⏳  Waiting for gateway to start …")
    if check_health(timeout=40):
        time.sleep(0.3)
        print(f"✅  Gateway ready!  Opening → {GATEWAY_URL}\n")
        webbrowser.open(GATEWAY_URL)
    else:
        print(f"⚠️   Gateway did not respond in time.")
        print(f"     Open manually → {GATEWAY_URL}\n")


def ensure_port_available(port: int = 8000):
    """Detect if port is held by a stale process and release it."""
    try:
        out = subprocess.check_output(["lsof", "-t", f"-i:{port}"], stderr=subprocess.DEVNULL).decode().strip()
        if out:
            pids = [int(p) for p in out.split() if p.isdigit()]
            for pid in pids:
                if pid != os.getpid():
                    print(f"⚠️  Port {port} is occupied by PID {pid}. Cleaning up stale process …")
                    try:
                        os.kill(pid, 15)
                        time.sleep(0.5)
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass
            time.sleep(0.3)
    except Exception:
        pass


def main():
    print(BANNER)
    ensure_port_available(GATEWAY_PORT)

    t = threading.Thread(target=browser_opener, daemon=True)
    t.start()

    cmd = [
        sys.executable, "-m", "uvicorn",
        "core.gateway.app:app",
        "--host", GATEWAY_HOST,
        "--port", str(GATEWAY_PORT),
        "--reload",
        "--log-level", "info",
    ]

    print(f"🚀  Starting gateway   →  {GATEWAY_URL}")
    print(f"📊  Dashboard & Chat   →  {GATEWAY_URL}")
    print(f"🔍  API Inspector      →  {GATEWAY_URL}/docs")
    print("\n    Press  Ctrl+C  to shut down.\n")

    try:
        proc = subprocess.Popen(cmd, cwd=PROJECT_ROOT)
        proc.wait()
    except KeyboardInterrupt:
        print("\n\n🛑  Shutting down Sentinel …")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("✅  Shutdown complete. Goodbye!\n")
    except FileNotFoundError:
        print("❌  uvicorn not found. Run:  pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()

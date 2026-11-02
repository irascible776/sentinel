#!/usr/bin/env bash
# Sentinel AI Security Gateway — Shell Stopper Wrapper
# Usage:
#   ./stop.sh          (Graceful shutdown)
#   ./stop.sh --force  (Immediate SIGKILL)
#   ./stop.sh --gateway-only
#   ./stop.sh --dashboard-only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    exec python3 "${SCRIPT_DIR}/stop.py" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "${SCRIPT_DIR}/stop.py" "$@"
else
    echo "⚠️  python3 not found in PATH. Using fallback shell cleanup..."
    GATEWAY_PORT=8000
    DASHBOARD_PORT=8501

    for port in $GATEWAY_PORT $DASHBOARD_PORT; do
        if command -v fuser >/dev/null 2>&1; then
            fuser -k "${port}/tcp" 2>/dev/null || true
        elif command -v lsof >/dev/null 2>&1; then
            pids=$(lsof -t -i:"${port}" 2>/dev/null || true)
            if [ -n "$pids" ]; then
                kill -15 $pids 2>/dev/null || true
                sleep 1
                kill -9 $pids 2>/dev/null || true
            fi
        fi
    done
    echo "✅ Fallback cleanup complete for ports 8000 & 8501."
fi

#!/bin/sh
# SENTINEL service orchestration: analyzer (:8710) + reports (:8711).
# Uses docker compose when a working docker daemon is present; otherwise
# falls back to local uvicorn processes from the component venvs.
# Usage: scripts/services.sh start|stop
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ANALYZER_PY="$ROOT/sentinel-analyzer/.venv/bin/python"
REPORTS_PY="$ROOT/sentinel-reports/.venv/bin/python"
A_PID=/tmp/sentinel-analyzer.pid
R_PID=/tmp/sentinel-reports.pid

docker_ok() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

health() {
    "$ANALYZER_PY" - "$1" <<'PY' >/dev/null 2>&1
import sys, urllib.request
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/health", timeout=2) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
}

# Kill anything still bound to a SENTINEL port: processes recorded in our
# pid files, plus any orphan listener (e.g. started before a code upgrade).
# A stale process would otherwise survive `start` forever and serve old code.
sweep_port() {
    if command -v lsof >/dev/null 2>&1; then
        pids=$(lsof -nP -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null || true)
        [ -n "$pids" ] && kill $pids >/dev/null 2>&1 || true
    fi
}

stop_local() {
    for f in "$A_PID" "$R_PID"; do
        if [ -f "$f" ]; then
            kill "$(cat "$f")" >/dev/null 2>&1
            rm -f "$f"
        fi
    done
    sweep_port 8710
    sweep_port 8711
}

case "${1:-}" in
start)
    if docker_ok; then
        cd "$ROOT" && docker compose up -d analyzer reports
        exit $?
    fi
    echo "docker daemon not found - starting local services from venvs"
    [ -x "$ANALYZER_PY" ] || { echo "missing analyzer venv - run: make build"; exit 1; }
    [ -x "$REPORTS_PY" ] || { echo "missing reports venv - run: make build"; exit 1; }
    # Always restart local services so the running code matches the tree.
    stop_local
    sleep 1
    ( cd "$ROOT/sentinel-reports" && nohup "$REPORTS_PY" -m uvicorn src.service:app --host 127.0.0.1 --port 8711 >/tmp/sentinel-reports.log 2>&1 & echo $! >"$R_PID" )
    ( cd "$ROOT/sentinel-analyzer" && nohup "$ANALYZER_PY" -m uvicorn src.main:app --host 127.0.0.1 --port 8710 >/tmp/sentinel-analyzer.log 2>&1 & echo $! >"$A_PID" )
    i=0
    while [ $i -lt 30 ]; do
        if health 8710 && health 8711; then
            echo "services up: analyzer :8710 | reports :8711 (local mode)"
            exit 0
        fi
        i=$((i + 1))
        sleep 1
    done
    echo "services failed to start - see /tmp/sentinel-analyzer.log and /tmp/sentinel-reports.log"
    exit 1
    ;;
stop)
    if docker_ok; then
        cd "$ROOT" && docker compose down
    fi
    stop_local
    exit 0
    ;;
*)
    echo "usage: $0 start|stop" >&2
    exit 2
    ;;
esac

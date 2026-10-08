#!/usr/bin/env bash
# ==============================================================================
# Chameleon Honeypot — Linux Daemon Management Script
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${SCRIPT_DIR}/bin/chameleon"
CONFIG_PATH="${SCRIPT_DIR}/config/config.json"
PID_FILE="${SCRIPT_DIR}/logs/chameleon.pid"
LOG_FILE="${SCRIPT_DIR}/logs/chameleon_stdout.log"

mkdir -p "${SCRIPT_DIR}/logs"

start_daemon() {
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        echo "[!] Chameleon is already running (PID: $(cat "${PID_FILE}"))"
        exit 1
    fi

    if [ ! -f "${BIN_PATH}" ]; then
        echo "[*] Binary not found. Building now..."
        (cd "${SCRIPT_DIR}" && go build -o "${BIN_PATH}" ./cmd/chameleon)
    fi

    echo "[*] Starting Chameleon Honeypot in background mode..."
    nohup "${BIN_PATH}" -c "${CONFIG_PATH}" > "${LOG_FILE}" 2>&1 &
    local pid=$!
    echo "${pid}" > "${PID_FILE}"
    echo "[+] Chameleon started successfully (PID: ${pid}). Logs: ${LOG_FILE}"
}

stop_daemon() {
    if [ ! -f "${PID_FILE}" ]; then
        echo "[!] PID file not found. Chameleon may not be running."
        return
    fi

    local pid
    pid="$(cat "${PID_FILE}")"
    if kill -0 "${pid}" 2>/dev/null; then
        echo "[*] Stopping Chameleon Honeypot (PID: ${pid})..."
        kill -TERM "${pid}"
        
        # Wait for graceful shutdown
        local timeout=10
        while kill -0 "${pid}" 2>/dev/null && [ ${timeout} -gt 0 ]; do
            sleep 1
            timeout=$((timeout - 1))
        done

        if kill -0 "${pid}" 2>/dev/null; then
            echo "[!] Force killing process..."
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        echo "[+] Chameleon stopped."
    else
        echo "[!] Process ${pid} is not running."
    fi
    rm -f "${PID_FILE}"
}

status_daemon() {
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        echo "[+] Chameleon is ACTIVE and RUNNING (PID: $(cat "${PID_FILE}"))"
    else
        echo "[-] Chameleon is STOPPED."
    fi
}

run_foreground() {
    if [ ! -f "${BIN_PATH}" ]; then
        echo "[*] Binary not found. Building now..."
        (cd "${SCRIPT_DIR}" && go build -o "${BIN_PATH}" ./cmd/chameleon)
    fi
    exec "${BIN_PATH}" -c "${CONFIG_PATH}" "$@"
}

case "${1:-run}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        stop_daemon
        sleep 1
        start_daemon
        ;;
    status)
        status_daemon
        ;;
    run)
        shift || true
        run_foreground "$@"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|run}"
        exit 1
        ;;
esac

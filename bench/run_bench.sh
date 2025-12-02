#!/usr/bin/env bash
set -euo pipefail

CGROUP="/sys/fs/cgroup/prefetch"
TEST_PROG="./bench_file_faults"

echo "[+] Creating cgroup at $CGROUP"
sudo mkdir -p "$CGROUP"
sudo chown $USER:$(id -gn) "$CGROUP"

echo "[+] Enabling subtree controllers"
(
    cd /sys/fs/cgroup
    echo "+memory" 2>/dev/null | sudo tee cgroup.subtree_control >/dev/null || true
    echo "+pids"   2>/dev/null | sudo tee cgroup.subtree_control >/dev/null || true
)

echo "[+] Compiling benchmark"
gcc -O2 bench_file_faults.c -o bench_file_faults

echo "[+] Launching benchmark"
$TEST_PROG "$@" &
PID=$!

echo "[+] PID = $PID"
echo "[+] Moving into cgroup"
echo $PID | sudo tee "$CGROUP/cgroup.procs" >/dev/null

echo "[+] Waiting for benchmark..."
wait $PID

echo "[+] Done."

#!/usr/bin/env bash
set -e

CGROUP="/sys/fs/cgroup/prefetch"
TEST_PROG="./test_memory_ops"

echo "[+] Creating cgroup at $CGROUP"
sudo mkdir -p "$CGROUP"
sudo chown $USER:$(id -gn) "$CGROUP"

# Enable basic controllers for safety (idempotent)
echo "[+] Enabling subtree controllers"
(
    cd /sys/fs/cgroup
    echo "+memory" 2>/dev/null | sudo tee cgroup.subtree_control >/dev/null || true
    echo "+pids"   2>/dev/null | sudo tee cgroup.subtree_control >/dev/null || true
)

echo "[+] Compiling test program"
gcc -O2 test_memory_ops.c -o test_memory_ops

echo "[+] Starting test program (will get moved into cgroup immediately)"

# Launch the program in background paused
$TEST_PROG &
PID=$!

echo "[+] Test program PID = $PID"
echo "[+] Moving process into cgroup"
echo $PID | sudo tee "$CGROUP/cgroup.procs" >/dev/null

echo "[+] Waiting for program to finish..."
wait $PID

echo "[+] Done."

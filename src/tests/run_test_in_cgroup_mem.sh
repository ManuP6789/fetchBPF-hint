#!/usr/bin/env bash
set -e

# --------------------------------------------------
# Usage:
#   ./run_test_in_cgroup.sh anon      # runs test_memory_ops
#   ./run_test_in_cgroup.sh major     # runs test_major_faults
# --------------------------------------------------

MODE="$1"

if [[ -z "$MODE" ]]; then
    echo "Usage: $0 {anon|major}"
    exit 1
fi

CGROUP="/sys/fs/cgroup/prefetch"

echo "[+] Disabling Transparent Huge Pages (THP)"
sudo bash -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled'
sudo bash -c 'echo never > /sys/kernel/mm/transparent_hugepage/defrag'

echo "[+] Disabling static HugePages"
sudo bash -c 'echo 0 > /proc/sys/vm/nr_hugepages'

echo "[+] THP status:"
cat /sys/kernel/mm/transparent_hugepage/enabled
echo "[+] nr_hugepages: $(cat /proc/sys/vm/nr_hugepages)"

echo "[+] Creating cgroup at $CGROUP"
sudo mkdir -p "$CGROUP"
sudo chown $USER:$(id -gn) "$CGROUP"

# Enable controllers
echo "[+] Enabling subtree controllers"
(
    cd /sys/fs/cgroup
    echo "+memory" | sudo tee cgroup.subtree_control >/dev/null || true
    echo "+pids"   | sudo tee cgroup.subtree_control >/dev/null || true
)

MB=128   # 50% of 256MB file

echo "[+] Setting memory.high = ${MB} MB"
echo $((MB * 1024 * 1024)) | sudo tee "$CGROUP/memory.high" >/dev/null

# --------------------------------------------------
# Choose test program based on MODE
# --------------------------------------------------
if [[ "$MODE" == "anon" ]]; then
    SRC="test_memory_ops.c"
    BIN="./test_memory_ops"
elif [[ "$MODE" == "major" ]]; then
    # Ensure file exists for major fault test
    echo "[+] Ensuring test_data.bin exists"
    # echo "1M" | sudo tee "$CGROUP/memory.max" >/dev/null
    ./gen_testfile.sh
    sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"
    SRC="test_major_faults.c"
    BIN="./test_major_faults"
else
    echo "Invalid mode: $MODE"
    echo "Allowed: anon   major"
    exit 1
fi

echo "[+] Compiling $SRC"
gcc -O2 "$SRC" -o "$BIN"

echo "[+] Starting test program ($BIN)"
$BIN &
PID=$!

echo "[+] Test program PID = $PID"
echo "[+] Moving process into cgroup"
echo $PID | sudo tee "$CGROUP/cgroup.procs" >/dev/null


echo "[+] Waiting for program to finish..."
wait $PID

echo "[+] Done."

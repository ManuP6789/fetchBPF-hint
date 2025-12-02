#!/usr/bin/env bash
set -e

FILE="test_data.bin"
SIZE_MB=256

if [ ! -f "$FILE" ]; then
    echo "[+] Generating test file using fallocate (no cache pollution)"
    fallocate -l ${SIZE_MB}M "$FILE"
else
    echo "[+] Test file already exists."
fi

echo "[+] Dropping page cache"
sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"

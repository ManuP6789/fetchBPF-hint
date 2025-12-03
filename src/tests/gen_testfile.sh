#!/usr/bin/env bash
set -e

FILE="test_data.bin"
SIZE_MB=512

if [ ! -f "$FILE" ]; then
    echo "[+] Trying fallocate for sparse, cold pages..."

    if fallocate -l ${SIZE_MB}M "$FILE" 2>/dev/null; then
        echo "[+] fallocate succeeded."
    else
        echo "[+] fallocate not supported. Using dd with direct I/O."
        dd if=/dev/zero of="$FILE" bs=1M count=$SIZE_MB oflag=direct status=progress
    fi
else
    echo "[+] Test file already exists."
fi

echo "[+] Forcing page cache drop"
sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"

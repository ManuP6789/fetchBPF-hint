#!/bin/bash
# silly.sh — example setup script for CloudLab nodes

set -eux  # exit on errors and print each command

# Update package lists
sudo apt update -y

# Install dependencies
sudo apt install -y clang libelf1 libelf-dev zlib1g-dev libssl-dev

# Install optional packages (uncomment if needed)
sudo apt install -y binutils-dev libcap-dev llvm gcc make build-essential

cd /local/repository/

git submodule update --init --recursive

# Install bpftool
cd third_party/bpftool/src

sudo make install

# Generate vmlinux.h for BPF CO:RE
cd ../../vmlinux/x86/

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

cd ../../../

make

echo "✅ Setup complete: clang and required libraries installed."

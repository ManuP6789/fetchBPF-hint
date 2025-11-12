#!/bin/bash
# silly.sh — example setup script for CloudLab nodes

set -eux  # exit on errors and print each command

# Update package lists
sudo apt update -y

# Install dependencies
sudo apt install -y clang libelf-dev zlib1g-dev

echo "✅ Setup complete: clang and required libraries installed."

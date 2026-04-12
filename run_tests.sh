#!/bin/bash
# Test script for passwordManager

set -e

APP="./build/passwordManager"

echo "=== Compiling ==="
cmake --build build

echo "=== Cleaning prior data ==="
rm -rf ~/.local/share/passwordManager
rm -rf ~/.config/passwordManager

echo "=== Test 1: Empty args ==="
$APP || true

echo "=== Test 2: Invalid command ==="
$APP unknowncmd || true

echo "=== Test 3: Create account ==="
echo "pwd123" | $APP create acc1

echo "=== Test 4: Add password ==="
# We need to provide account pass, then user pass
printf "pwd123\nsitepwd\n" | $APP add acc1 user1

echo "=== Test 5: View password ==="
printf "pwd123\n" | $APP view acc1 user1

echo "=== Test 6: Delete password ==="
printf "pwd123\n" | $APP remove acc1 user1
printf "pwd123\n" | $APP view acc1 user1 || true

echo "=== Test 7: Delete account ==="
printf "pwd123\n" | $APP delete acc1

echo "=== DONE ==="

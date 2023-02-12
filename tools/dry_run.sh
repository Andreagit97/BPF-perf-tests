#!/bin/bash
set -e
for f in "$1"/*; do
  echo "=== Run: '$f' ==="
  sudo "$f" --dry-run
  echo "=== End ==="
done

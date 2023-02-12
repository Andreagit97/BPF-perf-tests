#!/bin/bash
set -e
for f in "$1"/*; do
  echo "=== Run: '$f' ==="
  "$f" --dry-run
  echo "=== End ==="
done

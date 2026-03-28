#!/bin/bash

# set -e

# OLD_PROJECT="demo-portfolio-python-integration"
NEW_PROJECT="distributed-data-sync-platform"

# echo "=== STEP 1: Copy project ==="
# cp -r "$OLD_PROJECT" "$NEW_PROJECT"

# cd "$NEW_PROJECT"

echo "=== STEP 2: Rename models → domain ==="
if [ -d "src/models" ]; then
    mv src/models src/domain
fi

echo "=== STEP 3: Rename files (identity → source, target → destination) ==="

find src -type f | while read file; do
    dir=$(dirname "$file")
    base=$(basename "$file")

    new_base="$base"
    new_base="${new_base//identity/source}"
    new_base="${new_base//target/destination}"

    if [ "$base" != "$new_base" ]; then
        mv "$file" "$dir/$new_base"
    fi
done

echo "=== STEP 4: Replace inside files safely ==="

find src -type f -name "*.py" | while read file; do
    python3 - <<EOF
import io
import sys

path = "$file"

with open(path, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

content = content.replace("identity", "source")
content = content.replace("target", "destination")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
EOF
done

echo "=== STEP 5: Create pipelines ==="

mkdir -p src/pipelines

if [ -f "run_sync_engine.py" ]; then
    mv run_sync_engine.py src/pipelines/sync_pipeline.py
fi

if [ -f "run_identity_loader.py" ]; then
    mv run_identity_loader.py src/pipelines/file_pipeline.py
fi

echo "=== STEP 6: Remove sample data ==="

rm -rf data/sample 2>/dev/null || true

echo "=== STEP 7: Create README ==="

cat <<EOF > README.md
# Distributed Data Sync Platform

This project demonstrates a platform for synchronizing data between distributed systems.

## Architecture

Source System → Processing → Destination System

## Features

- State comparison between systems
- Incremental synchronization
- File-based processing
- Modular service architecture

## Use Cases

- Identity synchronization
- Data consistency across systems
- Backend integration pipelines

---

## Disclaimer

This project is fully anonymized and does not contain any client-specific data or proprietary logic.
EOF

echo "=== DONE ==="
echo "New project created: $NEW_PROJECT"
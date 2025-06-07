#!/bin/bash

# Get the project root based on script location
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# List of all output directories to clean
dirs=(
  output/processed
  output/topology
  output/reports/csv
  output/reports/diffs
  output/reports/html
  output/xml/processed
  output/xml/processed/raw
  output/xml/raw
  scripts/scanning/output/xml/raw
)

# Loop and delete files except .gitkeep
for dir in "${dirs[@]}"; do
  TARGET="$PROJECT_ROOT/$dir"
  if [ -d "$TARGET" ]; then
    find "$TARGET" -type f ! -name ".gitkeep" -delete
  fi
done

echo "🧹 Scan output cleaned (but .gitkeep files preserved)."

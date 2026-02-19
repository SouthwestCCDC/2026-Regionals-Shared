#!/bin/bash

# Read input from stdin
while IFS= read -r name; do
  # Create directory
  mkdir -p "$name"
  # Create README.md file with content
  echo -e "# $name\n" > "$name/README.md"
done

#**Usage:**
#```bash
#./create_directories.sh
# [paste the list of directory names]
# ctrl+d
#```

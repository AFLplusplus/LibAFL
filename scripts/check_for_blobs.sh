#!/bin/bash

declare -a blobs

KNOWN_GOOD_FILE_EXTENSIONS=("rs" "c" "h" "cc" "sh" "py" "toml" "yml" "json" "md" "gitignore" "png")

while read -r file; do
  # NOTE: mimetype detection spawns a perl process for each file and is pretty slow.
  # we work around this by skipping files with known-good extensions.
  ext="${file##*.}"
  for skipExt in "${KNOWN_GOOD_FILE_EXTENSIONS[@]}"; do
    if [ "$ext" = "$skipExt" ]; then
      continue 2
    fi
  done
  if mimetype -b "$file" | grep -Eq "application/(x-object|x-executable)"; then
    blobs+=("$file");
  fi
done < <(git ls-files --exclude-standard --cached --others)

if [ ${#blobs[@]} -eq 0 ]
then
  echo "No object or executable files in the root directory"
  exit 0
else
  echo "Hey! There are some object or executable file in the root directory!"
  echo "${blobs[@]}"
  echo "Aborting."
  exit 1
fi

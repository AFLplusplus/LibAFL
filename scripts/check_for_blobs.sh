#!/bin/bash

blobs=$(find . -type f -exec sh -c '
  for f; do 
    mimetype -b "$f" | grep -Eq "application/(x-object|x-executable)" && 
    printf "%s\n" "$f"
  done
' sh {} +)

if [ -z "$blobs" ]
then
  echo "No object or executable files in the root directory"
  exit 0
else
  echo "Hey! There are some object or executable file in the root directory!"
  echo "$blobs"
  echo "Aborting."
  exit 1
fi

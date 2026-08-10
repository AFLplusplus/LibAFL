#!/usr/bin/env bash
set -euo pipefail

# Go to the repo root
cd "$(dirname "$0")/.."

PACKAGES_TO_EXCLUDE=()
mapfile -t PACKAGES_TO_EXCLUDE < <(
  cargo metadata --no-deps --format-version 1 |
  jq -r --arg root "$(pwd)" \
    '.workspace_members as $members |
    .packages[] |
    select(.id | IN($members[])) |
    select(.manifest_path | startswith($root + "/utils/")) |
    .name
  '
)

EXCLUDE_ARGS=()
for PKG in "${PACKAGES_TO_EXCLUDE[@]}"; do
    EXCLUDE_ARGS+=("--exclude" "$PKG")
done

if [ ${#EXCLUDE_ARGS[@]} -gt 0 ]; then
  echo "The following packages will be excluded from publishing:"
  printf -- "- %s\n" "${PACKAGES_TO_EXCLUDE[@]}"
  echo ""
fi

echo "Running: cargo publish --workspace $* ${EXCLUDE_ARGS[*]}"
cargo publish --workspace "$@" "${EXCLUDE_ARGS[@]}"

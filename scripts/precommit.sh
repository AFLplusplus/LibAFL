#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

echo "[!] Running precommit script."
echo
echo
echo "[*] Formatting this beautiful code"
echo
"$SCRIPT_DIR"/fmt_all.sh || exit 1
echo
echo "[*] Asking clippy how to excel"
echo
"$SCRIPT_DIR"/clippy.sh || {
  echo "[!] Error: clippy wasn't succesful." >&2
  echo "[*] Hint: run scripts/autofix.sh to fix a bunch of errors automatically." >&2
  exit 1  # Exit the script with a non-zero status.
}
echo
echo "[!] All done. Ready to commit!"
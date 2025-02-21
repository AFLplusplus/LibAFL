#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

echo "[*] Formatting this beautiful code"
echo
"$SCRIPT_DIR"/fmt_all.sh || exit 1
echo
echo "[*] Asking clippy how to excel"
echo
"$SCRIPT_DIR"/fmt_all.sh || exit 1
echo
echo "[!] All done. Ready to commit!"

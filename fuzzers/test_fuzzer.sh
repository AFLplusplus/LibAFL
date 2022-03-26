if [ "$1" != "--no-fmt" ]; then
	
	echo "[*] Checking fmt for $fuzzer"
	# cargo fmt --all -- --check || exit 1
	echo "[*] Running clippy for $fuzzer"
	cargo clippy || exit 1
else
	echo "[+] Skipping fmt and clippy for $fuzzer (--no-fmt specified)"
fi

if [ -e ./Makefile.toml ]; then
	echo "[*] Testing $fuzzer"
	cargo make test || exit 1
	echo "[+] Done testing $fuzzer"
else
	echo "[*] Building $fuzzer"
	cargo build || exit 1
	echo "[+] Done building $fuzzer"
fi
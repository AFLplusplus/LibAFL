#!/usr/bin/env python3

import os
import subprocess
import sys
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing
import logging


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Run Clippy on fuzzers in parallel.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show commands without executing."
    )
    parser.add_argument(
        "--pedantic", action="store_true", help="Activate all clippy warnings"
    )
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    if args.dry_run:
        logging.info("Dry-run mode enabled. Commands will not be executed.")

    # Set directories
    script_dir = Path(__file__).resolve().parent
    libafl_dir = script_dir.parent
    os.chdir(libafl_dir)
    logging.debug(f"Changed directory to {libafl_dir}")

    # Initialize git submodules
    cmd = "git submodule update --init"
    logging.info(f"Running: {cmd}")
    if not args.dry_run:
        subprocess.run(cmd, shell=True, check=True)

    # Find fuzzer directories
    fuzzers = list((libafl_dir / "fuzzers").glob("*/*"))
    fuzzers.extend(list((libafl_dir / "fuzzers/baby/backtrace_baby_fuzzers").glob("*")))

    fuzzers = [f for f in fuzzers if "nyx_" not in f.name and f.is_dir()]
    logging.debug(f"Found {len(fuzzers)} fuzzers.")

    # Function to run commands
    def run_clippy(fuzzer: Path):
        if not (fuzzer / "Cargo.toml").is_file():
            logging.info(f"No Cargo.toml for {fuzzer}, skipping…")
            return True

        options = "-D clippy::pedantic" if args.pedantic else ""

        cmd_default = f"cargo clippy -- -D warnings {options}"
        cmd_nightly = f"cargo +nightly clippy -- -D warnings {options}"
        for cmd in [cmd_default, cmd_nightly]:
            logging.info(f"[{fuzzer}] Running: {cmd}")
            if args.dry_run:
                continue
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=fuzzer,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                logging.error(
                    f"[{fuzzer}] Command failed: cd {fuzzer}; {cmd}\n{result.stderr}"
                )
                return False
            else:
                logging.info(f"[{fuzzer}] Clippy passed.")

        return True

    # Run Clippy in parallel
    with ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
        futures = {executor.submit(run_clippy, fuzzer): fuzzer for fuzzer in fuzzers}
        success = True
        for future in as_completed(futures):
            if not future.result():
                success = False

    if success:
        logging.info("All fuzzers passed Clippy.")
        sys.exit(0)
    else:
        logging.error("Some fuzzers failed Clippy.")
        sys.exit(1)


if __name__ == "__main__":
    main()

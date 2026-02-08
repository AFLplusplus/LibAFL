#!/usr/bin/env python3
import os
import subprocess
import sys


def run_docs(root_dir):
    print(f"Searching for Justfiles in {root_dir}...")
    for dirpath, _, filenames in os.walk(root_dir):
        if "Justfile" in filenames:
            justfile_path = os.path.join(dirpath, "Justfile")
            # Check if 'doc' recipe exists
            try:
                # We use just --list to check for the recipe to avoid parsing
                # We use shell=False for security, but on Windows just might need shell=True if it's a batch file?
                # 'just' is usually an exe.
                result = subprocess.run(
                    ["just", "-f", justfile_path, "--list"],
                    capture_output=True,
                    text=True,
                    check=True,
                )

                # Parse just --list output
                has_doc = False
                for line in result.stdout.splitlines():
                    stripped = line.strip()
                    # Check for 'doc' recipe (exact match or followed by space/colon)
                    # just --list output format: "    recipe    # comment"
                    if stripped.startswith("doc") and (
                        len(stripped) == 3 or stripped[3] == " " or stripped[3] == ":"
                    ):
                        has_doc = True
                        break

                if has_doc:
                    print(f"Building docs in {dirpath} (via just)")
                    subprocess.run(["just", "-f", justfile_path, "doc"], check=True)
                else:
                    print(f"Building docs in {dirpath} (via cargo)")
                    # Fallback to cargo doc
                    subprocess.run(
                        ["cargo", "doc", "--no-deps", "--all-features"],
                        cwd=dirpath,
                        check=True,
                    )
            except subprocess.CalledProcessError as e:
                # If just --list fails, it might be a malformed Justfile or no recipes.
                # We can try cargo doc anyway if it's a rust crate.
                print(f"Warning: checking {justfile_path} failed: {e}")
                print(f"Attempting cargo doc fallback for {dirpath}")
                try:
                    subprocess.run(
                        ["cargo", "doc", "--no-deps", "--all-features"],
                        cwd=dirpath,
                        check=True,
                    )
                except subprocess.CalledProcessError as e2:
                    print(f"Error running cargo doc in {dirpath}: {e2}")
                    sys.exit(1)


if __name__ == "__main__":
    # Resolve script directory to make it location-independent
    script_dir = os.path.dirname(os.path.realpath(__file__))
    root_dir = os.path.dirname(script_dir)

    # Change to root directory
    os.chdir(root_dir)

    # Run for crates and utils
    run_docs("crates")
    run_docs("utils")

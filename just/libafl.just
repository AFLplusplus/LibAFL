# Main Justfile for LibAFL
# Provides multiple useful variables.
#
# Must be set:
#   - `FUZZER_NAME`: Name of the executable.
#
# Provides:
#   - `PROFILE`: Profile (either `dev` or `release`). Default is `release`.
#   - `PROFILE_DIR`: Profile directory (either `debug` or `release`).
#   - `TARGET_DIR`: target directry. Defaults to `target`.
#   - `BUILD_DIR`: Root directory in which the program is compiled.
#   - `FUZZER`: Executable path.

PROFILE := env("PROFILE", "release")
FUZZER_EXTENSION := if os_family() == "windows" { ".exe" } else { "" }
FUZZER := BUILD_DIR / FUZZER_NAME + FUZZER_EXTENSION

PROJECT_DIR := absolute_path(".")
PROFILE_DIR := if PROFILE == "dev" { "debug" } else { "release" }
TARGET_DIR := absolute_path(env("TARGET_DIR", "target"))
BUILD_DIR := TARGET_DIR / PROFILE_DIR

JUSTHASHES := ".justhashes"

buildfile fpath:
    #!/bin/bash

    # Init hash files if does not exit
    if [ ! -f {{ JUSTHASHES }} ]; then
        touch {{ JUSTHASHES }}
    fi

    if [ -d {{ fpath }}]
        echo "{{ fpath }} already exists as dir."
        exit 1
    fi

    # Run the file recipe if it changed or was not built before
    if [ ! -f {{ fpath }} ] || [ ! "$(md5sum {{ fpath }} | head -c 32)" == "$(grep " {{ fpath }}" {{ JUSTHASHES }} | head -c 32)" ]; then
        just {{ fpath }}
        echo "$(grep -v "{{ fpath }}" {{ JUSTHASHES }})" > {{ JUSTHASHES }}
        md5sum {{ fpath }} >> {{ JUSTHASHES }}
    fi

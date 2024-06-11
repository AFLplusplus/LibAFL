#!/bin/bash

RUST_LOG=debug ./fuzzer_libpng_launcher --cores 0-1 --input ./corpus --parent-addr 0.0.0.0:50000 --broker-port 3000 2>&1 | tee child.txt
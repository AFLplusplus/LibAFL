#!/bin/bash

RUST_LOG=info ./fuzzer_libpng_launcher --cores 2-3 --input ./corpus --nb-children 1 2>&1 | tee parent.txt
#!/bin/bash

RUST_LOG=info ./fuzzer_libpng_launcher --cores 2-3 --input ./corpus 2>parent.txt
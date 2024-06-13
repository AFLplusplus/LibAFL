#!/bin/bash

RUST_LOG=info ./ossfuzz --cores 2-3 --input ./corpus 2>parent.txt

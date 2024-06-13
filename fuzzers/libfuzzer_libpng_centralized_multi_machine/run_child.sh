#!/bin/bash

RUST_LOG=info ./ossfuzz --cores 0-1 --input ./corpus --parent-addr 0.0.0.0:50000 --broker-port 3000 2>child.txt

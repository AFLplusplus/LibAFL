#!/bin/sh

rm -rf ./crashes
rm -rf ./forkserver_simple

cargo build --release || exit 1

cp ./target/release/forkserver_simple .

timeout 5s ./forkserver_simple 2>/dev/null

rm -rf ./forkserver_simple
exit 0
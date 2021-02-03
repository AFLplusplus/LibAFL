#!/bin/sh

cargo build --release || exit 1
cp ./target/release/libfuzzer ./.libfuzzer_test.elf

RUST_BACKTRACE=full taskset -c 0 ./.libfuzzer_test.elf &

test "$!" -gt 0 && {

  usleep 250
  RUST_BACKTRACE=full taskset -c 1 ./.libfuzzer_test.elf &

}

sleep 20
echo "[+] Done"
killall .libfuzzer_test.elf
rm -rf ./.libfuzzer_test.elf

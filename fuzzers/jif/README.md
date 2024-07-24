# JIF - Javascript Injection Fuzzer

## building

* setup a chromium repo: https://www.chromium.org/developers/how-tos/get-the-code
    * note that this will take several hours
    * you MUST use revision: fc68e53944be7
* `mv jif $root/chromium/src/headless/jif` (or symbolic link appropriately)
* `cd $root/chromium/src`
* `python3 tools/mb/mb.py gen -m chromium.fuzz -b 'Libfuzzer Upload Mac ASan' out/jif`
*  apply patches in chromium_patches.diff
* `cp args.gn $root/chromium/src/out/jif/` (modify this so the fixed path points to your directory!)
* modify fixed path in `libafl_cc.rs` so it points to the correct place
* `./make.sh` (first time will take several hours, after that about 1m)

## running

* `cd $root/chromium/src/out/jif`
* `./jif --cores 0-3 --broker-port 1337 --harness harness.js -i corpus -x dict -o out`
* to see arguments, run `./jif --help`

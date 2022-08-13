# LibAFL Utils

Welcome to the LibAFL Utils folder.
Here, you find some helful utilities that may be helpful for successfull fuzzing campaigns.

## DeExit: ldpreload exit lib

In the `deexit` folder, you'll find a ldpreloadable library, that changes calls to `exit` to `abort()`s.
When a target exits, it quits, and LibAFL will not be able to catch this or recover.
Abort, on the other hand, raises an error LibAFL's inprocess executor will be able to catch, thanks to its signal handlers.

## Gramatron: gramatron grammars and preprocessing utils

See https://github.com/HexHive/Gramatron

## libafl_benches

This folder contains benchmarks for various things in LibAFL, like hash speeds and RNGs.
Run with `cargo bench`
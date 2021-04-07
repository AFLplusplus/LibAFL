#!/bin/sh
# Clippy checks
cargo clean
RUST_BACKTRACE=full cargo clippy --all -- \
   -D clippy::pedantic \
   -W missing-docs \
   -W clippy::missing-errors-doc \
   -W clippy::similar-names \
   -A clippy::missing-docs-in-private-items \
   -A clippy::unseparated-literal-suffix \
   -A clippy::module-name-repetitions \
   -A clippy::unreadable-literal \
   -A clippy::if-not-else \
   #--allow clippy::print-with-newline \
   #--allow clippy::write-with-newline \

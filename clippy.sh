#!/bin/sh
# Clippy checks
cargo clean
RUST_BACKTRACE=full cargo clippy --all -- \
   -D clippy::pedantic \
   -W clippy::cast_sign_loss \
   -W clippy::similar-names \
   -W clippy::cast_ptr_alignment \
   -A missing-docs \
   -A clippy::doc_markdown \
   -A clippy::must-use-candidate \
   -A clippy::missing-errors-doc \
   -A clippy::cast-possible-truncation \
   -A clippy::used-underscore-binding \
   -A clippy::ptr-as-ptr \
   -A clippy::missing-panics-doc \
   -A clippy::missing-docs-in-private-items \
   -A clippy::unseparated-literal-suffix \
   -A clippy::module-name-repetitions \
   -A clippy::unreadable-literal \
   -A clippy::if-not-else \

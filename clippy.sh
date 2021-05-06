#!/bin/sh
# Clippy checks
cargo clean -p libafl
RUST_BACKTRACE=full cargo clippy --all --all-features --tests -- \
   -D clippy::pedantic \
   -W clippy::cast_sign_loss \
   -W clippy::similar-names \
   -W clippy::cast_ptr_alignment \
   -W clippy::cast_possible_wrap \
   -W clippy::unused_self \
   -W clippy::too_many_lines \
   -W clippy::option_if_let_else \
   -W clippy::must-use-candidate \
   -W clippy::if-not-else \
   -A clippy::type_repetition_in_bounds \
   -A clippy::missing-errors-doc \
   -A clippy::cast-possible-truncation \
   -A clippy::used-underscore-binding \
   -A clippy::ptr-as-ptr \
   -A clippy::missing-panics-doc \
   -A clippy::missing-docs-in-private-items \
   -A clippy::unseparated-literal-suffix \
   -A clippy::module-name-repetitions \
   -A clippy::unreadable-literal \

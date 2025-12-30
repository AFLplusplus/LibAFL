mod libafl_bolts 'crates/libafl_bolts/Justfile'
mod libafl 'crates/libafl/Justfile'
mod libafl_targets 'crates/libafl_targets/Justfile'

doc-all:
  just libafl_bolts doc
  just libafl doc
  just libafl_targets doc
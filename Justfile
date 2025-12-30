mod libafl_bolts 'crates/libafl_bolts/Justfile'
mod libafl 'crates/libafl/Justfile'
mod libafl_targets 'crates/libafl_targets/Justfile'
mod libafl_cc 'crates/libafl_cc/Justfile'

doc-all:
  just libafl_bolts doc
  just libafl doc
  just libafl_targets doc
  just libafl_cc doc
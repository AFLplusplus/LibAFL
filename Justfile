mod libafl_bolts 'crates/libafl_bolts/Justfile'
mod libafl 'crates/libafl/Justfile'
mod libafl_targets 'crates/libafl_targets/Justfile'
mod libafl_cc 'crates/libafl_cc/Justfile'
mod libafl_derive 'crates/libafl_derive/Justfile'
mod libafl_nyx 'crates/libafl_nyx/Justfile'

doc-all:
  just libafl_bolts doc
  just libafl doc
  just libafl_targets doc
  just libafl_cc doc
  just libafl_derive doc
  just libafl_nyx doc
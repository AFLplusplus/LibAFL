#![no_main]

use libfuzzer_sys::fuzz_target;
use cargo_fuzz_test::do_thing;

fuzz_target!(|data: &[u8]| do_thing(data));

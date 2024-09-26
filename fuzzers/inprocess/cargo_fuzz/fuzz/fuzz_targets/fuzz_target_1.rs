#![no_main]

use cargo_fuzz_test::do_thing;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| do_thing(data));

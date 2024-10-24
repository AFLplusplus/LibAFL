use std::{env::args_os, hint::black_box};

fn main() {
    let input = args_os().last().unwrap();
    let buf = input.as_encoded_bytes();

    if !buf.is_empty() && buf[0] == b'a' {
        let _do_something = black_box(0);
        if buf.len() > 1 && buf[1] == b'b' {
            let _do_something = black_box(0);
            if buf.len() > 2 && buf[2] == b'c' {
                panic!("Artificial bug triggered =)");
            }
        }
    }
}

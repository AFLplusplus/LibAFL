use std::{
    hint::black_box,
    io::{stdin, Read},
};

fn main() {
    let mut buf = Vec::new();
    stdin().read_to_end(&mut buf).unwrap();

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

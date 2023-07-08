mod args;

use {
    crate::args::Args,
    clap::Parser,
    std::{thread::sleep, time::Duration},
};

#[no_mangle]
extern "C" fn run_test(num: usize) {
    println!("OUT - test: {num:}");
    if num & 1 == 0 {
        eprintln!("ERR - test: {num:}");
    }
}

#[no_mangle]
extern "C" fn test(num: usize) {
    for i in 0..num {
        run_test(i);
        sleep(Duration::from_millis(250));
    }
}

fn main() {
    println!("Hello demo!");
    let args = Args::parse();
    println!("Args: {args:#?}");
    test(10);
}

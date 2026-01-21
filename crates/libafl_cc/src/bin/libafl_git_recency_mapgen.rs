use std::{env, path::PathBuf, process};

fn usage() -> ! {
    eprintln!("Usage: libafl_git_recency_mapgen --out <FILE> --bin <BINARY>");
    process::exit(2);
}

fn main() {
    let mut mapping_out: Option<PathBuf> = None;
    let mut bin: Option<PathBuf> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => mapping_out = Some(args.next().unwrap_or_else(|| usage()).into()),
            "--bin" => bin = Some(args.next().unwrap_or_else(|| usage()).into()),
            _ => usage(),
        }
    }

    let mapping_out = mapping_out.unwrap_or_else(|| usage());
    let bin = bin.unwrap_or_else(|| usage());

    let cwd = env::current_dir().expect("Failed to read current directory");
    if let Err(err) = libafl_cc::generate_git_recency_mapping(&mapping_out, &bin, &[], &cwd) {
        eprintln!("Failed to generate mapping: {err:?}");
        process::exit(1);
    }
}

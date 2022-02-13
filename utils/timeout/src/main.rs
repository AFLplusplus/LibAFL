use clap::{App, Arg};
use core::time::Duration;
use process_control::ChildExt;
use process_control::Control;
use std::process::Command;

fn main() {
    let res = App::new("timeout")
        .about("Cross-Platform timeout util")
        .arg(
            Arg::new("executable")
                .help("The executable to run")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("duration")
                .short('t')
                .help("The timeout duration in seconds")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("arguments")
                .help("Arguments passed to the executable")
                .setting(clap::ArgSettings::MultipleValues)
                .takes_value(true),
        )
        .get_matches();

    let executable = res.value_of("executable").unwrap();
    let args = match res.values_of("arguments") {
        Some(vec) => vec.map(|s| s.to_string()).collect::<Vec<String>>().to_vec(),
        None => [].to_vec(),
    };
    let timeout = res
        .value_of("duration")
        .unwrap()
        .to_string()
        .parse()
        .expect("Could not parse timeout in seconds");

    let child = Command::new(executable)
        .args(args)
        .spawn()
        .expect("Failed to execute the command!")
        .controlled()
        .time_limit(Duration::from_secs(timeout))
        .terminate_for_timeout()
        .wait();

    match child {
        Ok(_) => {
            println!("child exited.");
        }
        Err(_) => {
            println!("child timeouted");
        }
    }
}

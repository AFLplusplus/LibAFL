use std::iter;

use clap::{Parser, builder::Str};

#[derive(Default)]
pub struct Version;

impl From<Version> for Str {
    fn from(_: Version) -> Str {
        let version = [
            ("Build Timestamp:", env!("VERGEN_BUILD_TIMESTAMP")),
            ("Describe:", env!("VERGEN_GIT_DESCRIBE")),
            ("Commit SHA:", env!("VERGEN_GIT_SHA")),
            ("Commit Date:", env!("VERGEN_RUSTC_COMMIT_DATE")),
            ("Commit Branch:", env!("VERGEN_GIT_BRANCH")),
            ("Rustc Version:", env!("VERGEN_RUSTC_SEMVER")),
            ("Rustc Channel:", env!("VERGEN_RUSTC_CHANNEL")),
            ("Rustc Host Triple:", env!("VERGEN_RUSTC_HOST_TRIPLE")),
            ("Rustc Commit SHA:", env!("VERGEN_RUSTC_COMMIT_HASH")),
            ("Cargo Target Triple", env!("VERGEN_CARGO_TARGET_TRIPLE")),
        ]
        .iter()
        .map(|(k, v)| format!("{k:25}: {v}\n"))
        .collect::<String>();

        format!("\n{version:}").into()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[command(
    version = Version::default(),
    about = "nosalr",
    long_about = "Tool launching applications with ASLR disabled"
)]
#[readonly::make]
pub struct Args {
    #[arg(help = "Name of the application to launch")]
    program: String,

    #[arg(last = true, value_parser, value_delimiter = ' ', num_args = 1.., help = "Arguments passed to the target")]
    args: Vec<String>,
}

impl Args {
    pub fn argv(&self) -> Vec<String> {
        iter::once(&self.program)
            .chain(self.args.iter())
            .cloned()
            .collect::<Vec<String>>()
    }
}

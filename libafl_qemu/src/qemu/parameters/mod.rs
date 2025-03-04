pub mod config;
pub use config::QemuConfig;

pub mod augmented_cli;
pub use augmented_cli::AugmentedCli;

#[derive(Clone, Debug)]
pub enum QemuParams {
    // QemuConfig is quite big, at least 240 bytes so we use a Box
    Config(Box<QemuConfig>),
    Cli(Vec<String>),
    AugmentedCli(AugmentedCli),
}

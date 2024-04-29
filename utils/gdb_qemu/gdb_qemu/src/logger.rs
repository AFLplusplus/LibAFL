use {
    crate::args::LogArgs,
    anyhow::{anyhow, Result},
    simplelog::{Config, LevelFilter, WriteLogger},
    std::fs::File,
};

pub struct Logger;

impl Logger {
    pub fn init(args: &impl LogArgs) -> Result<()> {
        let filter: LevelFilter = args.log_level().into();
        if filter != LevelFilter::Off {
            let logfile = File::create(args.log_file())
                .map_err(|e| anyhow!("Failed to open log file: {e:}"))?;
            WriteLogger::init(filter, Config::default(), logfile)
                .map_err(|e| anyhow!("Failed to initalize logger: {e:}"))?;
        }
        Ok(())
    }
}

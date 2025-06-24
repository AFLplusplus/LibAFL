use alloc::{boxed::Box, format};

use log::{Level, LevelFilter, Log, Metadata, Record};
use rustix::{io::write, stdio::stderr};
use spin::Once;

static ONCE: Once<&'static LinuxLogger> = Once::new();

pub struct LinuxLogger {
    level: Level,
}

impl LinuxLogger {
    pub fn initialize(level: Level) {
        ONCE.call_once(|| {
            let logger = Box::leak(Box::new(LinuxLogger { level }));
            log::set_logger(logger).unwrap();
            log::set_max_level(LevelFilter::Trace);
            logger
        });
    }
}

impl Log for LinuxLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.level >= metadata.level()
    }

    fn flush(&self) {}

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let formatted = format!(
                "{} [{}]: {}\n",
                record.metadata().level(),
                record.metadata().target(),
                record.args()
            );
            let buf = formatted.as_bytes();
            #[allow(unused_unsafe)]
            let fd = unsafe { stderr() };
            write(fd, buf).unwrap();
        }
    }
}

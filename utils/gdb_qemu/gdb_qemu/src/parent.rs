use std::{
    fmt,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    os::fd::RawFd,
    thread::spawn,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Result};
use nix::unistd::read;

use crate::{args::ParentArgs, exit::Exit};

enum Direction {
    GdbToTarget,
    TargetToGdb,
}

impl fmt::Display for Direction {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Direction::GdbToTarget => write!(fmt, "GDB --> TGT"),
            Direction::TargetToGdb => write!(fmt, "GDB <-- TGT"),
        }
    }
}

enum Channel {
    Stdout,
    StdErr,
}

impl fmt::Display for Channel {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Channel::Stdout => write!(fmt, "[STDOUT]"),
            Channel::StdErr => write!(fmt, "[STDERR]"),
        }
    }
}

pub struct Parent {
    port: u16,
    timeout: u64,
    fd1: RawFd,
    fd2: RawFd,
}

impl Parent {
    const BUFFER_SIZE: usize = 16 << 10;

    pub fn new(args: &impl ParentArgs, fd1: RawFd, fd2: RawFd) -> Parent {
        Parent {
            port: args.port(),
            timeout: args.timeout(),
            fd1,
            fd2,
        }
    }

    fn log_packets(direction: &Direction, buffer: &[u8]) -> Result<()> {
        for pkt in String::from_utf8_lossy(buffer)
            .split('$')
            .filter(|x| !x.is_empty())
            .filter(|x| x != &"+")
        {
            trace!("{direction:} - ${pkt:}");
        }
        Ok(())
    }

    fn log_io(channel: &Channel, buffer: &[u8]) -> Result<()> {
        for line in String::from_utf8_lossy(buffer)
            .lines()
            .filter(|x| !x.is_empty())
        {
            trace!("{channel:} - {line:}");
        }
        Ok(())
    }

    fn pump(input: &mut impl Read, output: &mut impl Write, direction: Direction) -> Result<()> {
        let mut buffer = [0u8; Parent::BUFFER_SIZE];
        loop {
            let n = input
                .read(&mut buffer)
                .map_err(|e| anyhow!("Failed to read input: {e:}"))?;
            if n == 0 {
                break;
            }

            Parent::log_packets(&direction, &buffer[..n])?;

            output
                .write_all(&buffer[..n])
                .map_err(|e| anyhow!("Failed to write output: {e:}"))?;
            output
                .flush()
                .map_err(|e| anyhow!("Failed to flush output: {e:}"))?;
        }
        Ok(())
    }

    fn pumpfd(input: RawFd, output: &mut impl Write, channel: Channel) -> Result<()> {
        let mut buffer = [0u8; Parent::BUFFER_SIZE];
        loop {
            let n = read(input, &mut buffer).map_err(|e| anyhow!("Failed to read input: {e:}"))?;
            if n == 0 {
                break;
            }

            Parent::log_io(&channel, &buffer[..n])?;

            output
                .write_all(&buffer[..n])
                .map_err(|e| anyhow!("Failed to write output: {e:}"))?;
            output
                .flush()
                .map_err(|e| anyhow!("Failed to flush output: {e:}"))?;
        }
        Ok(())
    }

    fn connect(&self) -> Result<TcpStream> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let timeout = Duration::from_millis(self.timeout);

        let now = SystemTime::now();

        loop {
            let result = TcpStream::connect(addr);
            if let Ok(stream) = result {
                return Ok(stream);
            }

            let elapsed = now
                .elapsed()
                .map_err(|e| anyhow!("Failed to measure elapsed time: {e:}"))?;

            if elapsed > timeout {
                return result.map_err(|e| anyhow!("Failed to connect: {e:}"));
            }
        }
    }

    pub fn run(&self) -> Result<()> {
        let stream = self.connect()?;
        info!("Connected to client: {stream:#?}");

        let mut read_stream = stream
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone read_stream: {e:}"))?;
        let mut stdout = std::io::stdout();
        let reader = spawn(move || {
            Self::pump(&mut read_stream, &mut stdout, Direction::TargetToGdb).unwrap()
        });

        let mut stdin = std::io::stdin();
        let mut write_stream = stream
            .try_clone()
            .map_err(|e| anyhow!("Failed to clone write_stream: {e:}"))?;
        let writer = spawn(move || {
            Self::pump(&mut stdin, &mut write_stream, Direction::GdbToTarget).unwrap()
        });

        let mut stderr1 = std::io::stderr();
        let fd1 = self.fd1;
        let stdout_pump = spawn(move || Self::pumpfd(fd1, &mut stderr1, Channel::Stdout).unwrap());

        let mut stderr2 = std::io::stderr();
        let fd2 = self.fd2;
        let stderr_pump = spawn(move || Self::pumpfd(fd2, &mut stderr2, Channel::StdErr).unwrap());

        reader
            .join()
            .map_err(|e| anyhow!("Failed to join reader: {e:#?}"))?;
        writer
            .join()
            .map_err(|e| anyhow!("Failed to join writer: {e:#?}"))?;
        stdout_pump
            .join()
            .map_err(|e| anyhow!("Failed to join stdout_pump: {e:#?}"))?;
        stderr_pump
            .join()
            .map_err(|e| anyhow!("Failed to join stderr_pump: {e:#?}"))?;

        Exit::wait_for_child()?;
        Ok(())
    }
}

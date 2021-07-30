use std::{
    io::Write,
    process::{Child, Command, Stdio},
};

use libafl::{
    executors::command::CommandConfigurator,
    inputs::{HasTargetBytes, Input},
    Error,
};

#[derive(Default)]
pub struct MyCommandConfigurator;

impl<EM, I, S, Z> CommandConfigurator<EM, I, S, Z> for MyCommandConfigurator
where
    I: HasTargetBytes + Input,
{
    fn spawn_child(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<Child, Error> {
        let mut command = Command::new("../if");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = command.spawn().expect("failed to start process");
        let mut stdin = child.stdin.as_ref().unwrap();
        stdin.write_all(input.target_bytes().as_slice())?;
        Ok(child)
    }
}

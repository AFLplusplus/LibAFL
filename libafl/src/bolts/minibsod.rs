//! Implements a mini-bsod generator

use std::io::{BufWriter, Write};

use libc::{siginfo_t, ucontext_t};

use crate::bolts::os::unix_signals::Signal;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn dump_registers<W: Write>(writer: &mut BufWriter<W>, ucontext: &ucontext_t) -> Result<(), std::io::Error>{
    use libc::{REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_RDI, REG_RSI, REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX, REG_RSP, REG_RIP, REG_EFL};

    let mcontext = &ucontext.uc_mcontext;

    write!(writer, "r8 : {:#016x}, ", mcontext.gregs[REG_R8 as usize])?;
    write!(writer, "r9 : {:#016x}, ", mcontext.gregs[REG_R9 as usize])?;
    write!(writer, "r10: {:#016x}, ", mcontext.gregs[REG_R10 as usize])?;
    writeln!(writer, "r11: {:#016x}, ", mcontext.gregs[REG_R11 as usize])?;
    write!(writer, "r12: {:#016x}, ", mcontext.gregs[REG_R12 as usize])?;
    write!(writer, "r13: {:#016x}, ", mcontext.gregs[REG_R13 as usize])?;
    write!(writer, "r14: {:#016x}, ", mcontext.gregs[REG_R14 as usize])?;
    writeln!(writer, "r15: {:#016x}, ", mcontext.gregs[REG_R15 as usize])?;
    write!(writer, "rdi: {:#016x}, ", mcontext.gregs[REG_RDI as usize])?;
    write!(writer, "rsi: {:#016x}, ", mcontext.gregs[REG_RSI as usize])?;
    write!(writer, "rbp: {:#016x}, ", mcontext.gregs[REG_RBP as usize])?;
    writeln!(writer, "rbx: {:#016x}, ", mcontext.gregs[REG_RBX as usize])?;
    write!(writer, "rdx: {:#016x}, ", mcontext.gregs[REG_RDX as usize])?;
    write!(writer, "rax: {:#016x}, ", mcontext.gregs[REG_RAX as usize])?;
    write!(writer, "rcx: {:#016x}, ", mcontext.gregs[REG_RCX as usize])?;
    writeln!(writer, "rsp: {:#016x}, ", mcontext.gregs[REG_RSP as usize])?;
    write!(writer, "rip: {:#016x}, ", mcontext.gregs[REG_RIP as usize])?;
    writeln!(writer, "efl: {:#016x}, ", mcontext.gregs[REG_EFL as usize])?;

    Ok(())
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn dump_registers<W: Write>(writer: &mut BufWriter<W>, ucontext: &ucontext_t) -> Result<(), std::io::Error>{
    for reg in 0..31 {
        write!(
            writer,
            "x{:02}: 0x{:016x} ",
            reg, ucontext.uc_mcontext.regs[reg as usize]
        );
        if reg % 4 == 3 {
            writeln!(writer, "");
        }
    }
    writeln!(writer, "pc : 0x{:016x} ", ucontext.uc_mcontext.pc);

    Ok(())
}

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
fn dump_registers<W: Write>(writer: &mut BufWriter<W>, ucontext: &ucontext_t) -> Result<(), std::io::Error>{
    let mcontext = *ucontext.uc_mcontext;
    for reg in 0..29 {
        writeln!(writer, "x{:02}: 0x{:016x} ", reg, mcontext.__ss.__x[reg as usize]);
        if reg % 4 == 3 {
            writeln!(writer, "");
        }
    }
    write!(writer, "fp: 0x{:016x} ", mcontext.__ss.__fp);
    write!(writer, "lr: 0x{:016x} ", mcontext.__ss.__lr);
    write!(writer, "pc: 0x{:016x} ", mcontext.__ss.__pc);

    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_crash<W: Write>(writer: &mut BufWriter<W>, signal: Signal, ucontext: &ucontext_t) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:#016x}, fault address: {:#016x}",
        signal, ucontext.uc_mcontext.gregs[libc::REG_RIP as usize], ucontext.uc_mcontext.gregs[libc::REG_CR2 as usize]
    )?;

    Ok(())
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn write_crash<W: Write>(writer: &mut BufWriter<W>, signal: Signal, ucontext: &ucontext_t) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at 0x{:016x}, fault address: 0x{:016x}",
        signal, ucontext.uc_mcontext.pc, ucontext.uc_mcontext.fault_address
    )?;

    Ok(())
}

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
fn write_crash<W: Write>(writer: &mut BufWriter<W>, signal: Signal, ucontext: &ucontext_t) -> Result<(), std::io::Error> {
    let mcontext = *ucontext.uc_mcontext;
    writeln!(
        writer,
        "Received signal {} at 0x{:016x}, fault address: 0x{:016x}",
        signal, mcontext.__ss.__pc, mcontext.__es.__far
    )?;

    Ok(())
}

/// Generates a mini-BSOD given a signal and context.
#[cfg(unix)]
pub fn generate_minibsod<W: Write>(writer: &mut BufWriter<W>, signal: Signal, _siginfo: &siginfo_t, ucontext: &ucontext_t) -> Result<(), std::io::Error> {
    writeln!(writer, "{:━^100}", " CRASH ")?;
    write_crash(writer, signal, ucontext)?;
    writeln!(writer, "{:━^100}", " REGISTERS ")?;
    dump_registers(writer, ucontext)?;
    writeln!(writer, "{:━^100}", " BACKTRACE ")?;
    writeln!(writer, "{:?}", backtrace::Backtrace::new())?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        writeln!(writer, "{:━^100}", " MAPS ")?;

        match std::fs::read_to_string("/proc/self/maps") {
            Ok(maps) => writer.write_all(maps.as_bytes())?,
            Err(e) => writeln!(writer, "Couldn't load mappings: {:?}", e)?,
        };
    }

    Ok(())
}

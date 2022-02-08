//! Implements a mini-bsod generator.
//! It dumps all important registers and prints a stacktrace.
//! You may use the [`crate::bolts::os::unix_signals::ucontext`]
//! function to get a [`ucontext_t`].

use libc::siginfo_t;
use std::io::{BufWriter, Write};

use crate::bolts::os::unix_signals::{ucontext_t, Signal};

/// Write the content of all important registers
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(clippy::similar_names)]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    use libc::{
        REG_EFL, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_R8, REG_R9, REG_RAX,
        REG_RBP, REG_RBX, REG_RCX, REG_RDI, REG_RDX, REG_RIP, REG_RSI, REG_RSP,
    };

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

/// Write the content of all important registers
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    for reg in 0..31 {
        write!(
            writer,
            "x{:02}: 0x{:016x} ",
            reg, ucontext.uc_mcontext.regs[reg as usize]
        )?;
        if reg % 4 == 3 {
            writeln!(writer)?;
        }
    }
    writeln!(writer, "pc : 0x{:016x} ", ucontext.uc_mcontext.pc)?;

    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "linux", target_arch = "arm"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    write!(writer, "r0 : {:#016x}, ", ucontext.uc_mcontext.arm_r0)?;
    write!(writer, "r1 : {:#016x}, ", ucontext.uc_mcontext.arm_r1)?;
    write!(writer, "r2: {:#016x}, ", ucontext.uc_mcontext.arm_r2)?;
    writeln!(writer, "r3: {:#016x}, ", ucontext.uc_mcontext.arm_r3)?;
    write!(writer, "r4: {:#016x}, ", ucontext.uc_mcontext.arm_r4)?;
    write!(writer, "r5: {:#016x}, ", ucontext.uc_mcontext.arm_r5)?;
    write!(writer, "r6: {:#016x}, ", ucontext.uc_mcontext.arm_r6)?;
    writeln!(writer, "r7: {:#016x}, ", ucontext.uc_mcontext.arm_r7)?;
    write!(writer, "r8: {:#016x}, ", ucontext.uc_mcontext.arm_r8)?;
    write!(writer, "r9: {:#016x}, ", ucontext.uc_mcontext.arm_r9)?;
    write!(writer, "r10: {:#016x}, ", ucontext.uc_mcontext.arm_r10)?;
    writeln!(writer, "fp: {:#016x}, ", ucontext.uc_mcontext.arm_fp)?;
    write!(writer, "ip: {:#016x}, ", ucontext.uc_mcontext.arm_ip)?;
    write!(writer, "sp: {:#016x}, ", ucontext.uc_mcontext.arm_sp)?;
    write!(writer, "lr: {:#016x}, ", ucontext.uc_mcontext.arm_lr)?;
    writeln!(writer, "cpsr: {:#016x}, ", ucontext.uc_mcontext.arm_cpsr)?;

    writeln!(writer, "pc : 0x{:016x} ", ucontext.uc_mcontext.arm_pc)?;

    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    let mcontext = unsafe { *ucontext.uc_mcontext };
    for reg in 0..29 {
        writeln!(
            writer,
            "x{:02}: 0x{:016x} ",
            reg, mcontext.__ss.__x[reg as usize]
        )?;
        if reg % 4 == 3 {
            writeln!(writer)?;
        }
    }
    write!(writer, "fp: 0x{:016x} ", mcontext.__ss.__fp)?;
    write!(writer, "lr: 0x{:016x} ", mcontext.__ss.__lr)?;
    write!(writer, "pc: 0x{:016x} ", mcontext.__ss.__pc)?;

    Ok(())
}

/// Write the content of all important registers
#[allow(clippy::unnecessary_wraps, clippy::similar_names)]
#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    let mcontext = unsafe { *ucontext.uc_mcontext };
    let ss = mcontext.__ss;

    write!(writer, "r8 : {:#016x}, ", ss.__r8)?;
    write!(writer, "r9 : {:#016x}, ", ss.__r9)?;
    write!(writer, "r10: {:#016x}, ", ss.__r10)?;
    writeln!(writer, "r11: {:#016x}, ", ss.__r11)?;
    write!(writer, "r12: {:#016x}, ", ss.__r12)?;
    write!(writer, "r13: {:#016x}, ", ss.__r13)?;
    write!(writer, "r14: {:#016x}, ", ss.__r14)?;
    writeln!(writer, "r15: {:#016x}, ", ss.__r15)?;
    write!(writer, "rdi: {:#016x}, ", ss.__rdi)?;
    write!(writer, "rsi: {:#016x}, ", ss.__rsi)?;
    write!(writer, "rbp: {:#016x}, ", ss.__rbp)?;
    writeln!(writer, "rbx: {:#016x}, ", ss.__rbx)?;
    write!(writer, "rdx: {:#016x}, ", ss.__rdx)?;
    write!(writer, "rax: {:#016x}, ", ss.__rax)?;
    write!(writer, "rcx: {:#016x}, ", ss.__rcx)?;
    writeln!(writer, "rsp: {:#016x}, ", ss.__rsp)?;
    write!(writer, "rip: {:#016x}, ", ss.__rip)?;
    writeln!(writer, "efl: {:#016x}, ", ss.__rflags)?;

    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    _ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    // TODO: Implement dump registers
    writeln!(
        writer,
        "< Dumping registers is not yet supported on platform {:?}. Please add it to `minibsod.rs` >",
        std::env::consts::OS
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:#016x}, fault address: {:#016x}",
        signal,
        ucontext.uc_mcontext.gregs[libc::REG_RIP as usize],
        ucontext.uc_mcontext.gregs[libc::REG_CR2 as usize]
    )?;

    Ok(())
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at 0x{:016x}, fault address: 0x{:016x}",
        signal, ucontext.uc_mcontext.pc, ucontext.uc_mcontext.fault_address
    )?;

    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "arm"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at 0x{:016x}, fault address: 0x{:016x}",
        signal, ucontext.uc_mcontext.arm_pc, ucontext.uc_mcontext.fault_address
    )?;

    Ok(())
}

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    let mcontext = unsafe { *ucontext.uc_mcontext };
    writeln!(
        writer,
        "Received signal {} at 0x{:016x}, fault address: 0x{:016x}",
        signal, mcontext.__ss.__pc, mcontext.__es.__far
    )?;

    Ok(())
}

#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
#[allow(clippy::similar_names)]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    let mcontext = unsafe { *ucontext.uc_mcontext };

    writeln!(
        writer,
        "Received signal {} at 0x{:016x}, fault address: 0x{:016x}, trapno: 0x{:x}, err: 0x{:x}",
        signal,
        mcontext.__ss.__rip,
        mcontext.__es.__faultvaddr,
        mcontext.__es.__trapno,
        mcontext.__es.__err
    )?;

    Ok(())
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    _ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    // TODO add fault addr for other platforms.
    writeln!(writer, "Received signal {}", signal,)?;

    Ok(())
}

/// Generates a mini-BSOD given a signal and context.
#[cfg(unix)]
#[allow(clippy::non_ascii_literal)]
pub fn generate_minibsod<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    _siginfo: siginfo_t,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
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

#[cfg(test)]
mod tests {

    use std::io::{stdout, BufWriter};

    use crate::bolts::{minibsod::dump_registers, os::unix_signals::ucontext};

    #[test]
    pub fn test_dump_registers() {
        let ucontext = ucontext().unwrap();
        let mut writer = BufWriter::new(stdout());
        dump_registers(&mut writer, &ucontext).unwrap();
    }
}

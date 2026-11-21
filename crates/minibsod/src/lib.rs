//! Implements a mini-bsod generator.
//! It dumps all important registers and prints a stacktrace.
#![doc = include_str!("../README.md")]
/*! */
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

#[macro_use]
extern crate std;
#[doc(hidden)]
pub extern crate alloc;

#[cfg(unix)]
use alloc::vec::Vec;
#[cfg(any(target_vendor = "apple", target_os = "openbsd"))]
use core::mem::size_of;
use std::io::{BufWriter, Write};
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
use std::process::Command;

#[cfg(unix)]
use exceptional::unix_signals::{Signal, ucontext_t};
#[cfg(unix)]
use libc::siginfo_t;
#[cfg(target_vendor = "apple")]
use mach2::{
    message::mach_msg_type_number_t,
    traps::mach_task_self,
    vm::mach_vm_region_recurse,
    vm_region::{vm_region_recurse_info_t, vm_region_submap_info_64},
    vm_types::{mach_vm_address_t, mach_vm_size_t, natural_t},
};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, EXCEPTION_POINTERS};

/// Necessary info to print a mini-BSOD.
#[derive(Debug)]
#[cfg(unix)]
pub struct BsodInfo {
    /// the signal
    pub signal: Signal,
    /// siginfo
    pub siginfo: siginfo_t,
    /// ucontext
    pub ucontext: Option<ucontext_t>,
}

/// Write the content of all important registers
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "x86_64"
))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    use libc::{
        REG_EFL, REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_RAX,
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
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    use libc::{
        REG_EAX, REG_EBP, REG_EBX, REG_ECX, REG_EDI, REG_EDX, REG_EFL, REG_EIP, REG_ESI, REG_ESP,
    };

    let mcontext = &ucontext.uc_mcontext;

    write!(writer, "eax: {:#016x}, ", mcontext.gregs[REG_EAX as usize])?;
    write!(writer, "ebx: {:#016x}, ", mcontext.gregs[REG_EBX as usize])?;
    write!(writer, "ecx: {:#016x}, ", mcontext.gregs[REG_ECX as usize])?;
    writeln!(writer, "edx: {:#016x}, ", mcontext.gregs[REG_EDX as usize])?;
    write!(writer, "edi: {:#016x}, ", mcontext.gregs[REG_EDI as usize])?;
    write!(writer, "esi: {:#016x}, ", mcontext.gregs[REG_ESI as usize])?;
    write!(writer, "esp: {:#016x}, ", mcontext.gregs[REG_ESP as usize])?;
    writeln!(writer, "ebp: {:#016x}, ", mcontext.gregs[REG_EBP as usize])?;
    write!(writer, "eip: {:#016x}, ", mcontext.gregs[REG_EIP as usize])?;
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
    for reg in 0..31_usize {
        write!(
            writer,
            "x{:02}: 0x{:016x} ",
            reg, ucontext.uc_mcontext.regs[reg]
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
#[cfg(all(target_os = "freebsd", target_arch = "aarch64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    let mcontext = &ucontext.uc_mcontext;
    for reg in 0..29_u8 {
        writeln!(
            writer,
            "x{:02}: 0x{:016x} ",
            reg, mcontext.mc_gpregs.gp_x[reg as usize]
        )?;
        if reg % 4 == 3 {
            writeln!(writer)?;
        }
    }
    write!(writer, "lr: 0x{:016x} ", mcontext.mc_gpregs.gp_lr)?;
    write!(writer, "sp: 0x{:016x} ", mcontext.mc_gpregs.gp_sp)?;

    Ok(())
}

/// Write the content of all important registers
///
/// # Safety
/// If `ucontext.uc_mcontext` is non-null and aligned, it must point to a valid, initialized
/// mcontext instance for the duration of this call.
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
pub unsafe fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    if ucontext.uc_mcontext.is_null() || !ucontext.uc_mcontext.is_aligned() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ucontext.uc_mcontext is null or unaligned",
        ));
    }
    let mcontext = unsafe { &*ucontext.uc_mcontext };
    for reg in 0..29_u8 {
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
///
/// # Safety
/// If `ucontext.uc_mcontext` is non-null and aligned, it must point to a valid, initialized
/// mcontext instance for the duration of this call.
#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
pub unsafe fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    if ucontext.uc_mcontext.is_null() || !ucontext.uc_mcontext.is_aligned() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ucontext.uc_mcontext is null or unaligned",
        ));
    }
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

/// Write the content of all important registers
#[cfg(all(
    any(target_os = "freebsd", target_os = "dragonfly"),
    target_arch = "x86_64"
))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    let mcontext = &ucontext.uc_mcontext;

    write!(writer, "r8 : {:#016x}, ", mcontext.mc_r8)?;
    write!(writer, "r9 : {:#016x}, ", mcontext.mc_r9)?;
    write!(writer, "r10 : {:#016x}, ", mcontext.mc_r10)?;
    write!(writer, "r11 : {:#016x}, ", mcontext.mc_r11)?;
    write!(writer, "r12 : {:#016x}, ", mcontext.mc_r12)?;
    write!(writer, "r13 : {:#016x}, ", mcontext.mc_r13)?;
    write!(writer, "r14 : {:#016x}, ", mcontext.mc_r14)?;
    write!(writer, "r15 : {:#016x}, ", mcontext.mc_r15)?;
    write!(writer, "rdi : {:#016x}, ", mcontext.mc_rdi)?;
    write!(writer, "rsi : {:#016x}, ", mcontext.mc_rsi)?;
    write!(writer, "rbp : {:#016x}, ", mcontext.mc_rbp)?;
    write!(writer, "rbx : {:#016x}, ", mcontext.mc_rbx)?;
    write!(writer, "rdx : {:#016x}, ", mcontext.mc_rdx)?;
    write!(writer, "rax : {:#016x}, ", mcontext.mc_rax)?;
    write!(writer, "rcx : {:#016x}, ", mcontext.mc_rcx)?;
    write!(writer, "rsp : {:#016x}, ", mcontext.mc_rsp)?;
    write!(writer, "rflags : {:#016x}, ", mcontext.mc_rflags)?;
    write!(writer, "cs : {:#016x}, ", mcontext.mc_cs)?;
    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "netbsd", target_arch = "x86_64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    use libc::{
        _REG_CS, _REG_R8, _REG_R9, _REG_R10, _REG_R11, _REG_R12, _REG_R13, _REG_R14, _REG_R15,
        _REG_RAX, _REG_RBP, _REG_RBX, _REG_RCX, _REG_RDI, _REG_RDX, _REG_RFLAGS, _REG_RIP,
        _REG_RSI, _REG_RSP,
    };

    let mcontext = &ucontext.uc_mcontext;

    write!(
        writer,
        "r8 : {:#016x}, ",
        mcontext.__gregs[_REG_R8 as usize]
    )?;
    write!(
        writer,
        "r9 : {:#016x}, ",
        mcontext.__gregs[_REG_R9 as usize]
    )?;
    write!(
        writer,
        "r10: {:#016x}, ",
        mcontext.__gregs[_REG_R10 as usize]
    )?;
    writeln!(
        writer,
        "r11: {:#016x}, ",
        mcontext.__gregs[_REG_R11 as usize]
    )?;
    write!(
        writer,
        "r12: {:#016x}, ",
        mcontext.__gregs[_REG_R12 as usize]
    )?;
    write!(
        writer,
        "r13: {:#016x}, ",
        mcontext.__gregs[_REG_R13 as usize]
    )?;
    write!(
        writer,
        "r14: {:#016x}, ",
        mcontext.__gregs[_REG_R14 as usize]
    )?;
    writeln!(
        writer,
        "r15: {:#016x}, ",
        mcontext.__gregs[_REG_R15 as usize]
    )?;
    write!(
        writer,
        "rdi: {:#016x}, ",
        mcontext.__gregs[_REG_RDI as usize]
    )?;
    write!(
        writer,
        "rsi: {:#016x}, ",
        mcontext.__gregs[_REG_RSI as usize]
    )?;
    write!(
        writer,
        "rbp: {:#016x}, ",
        mcontext.__gregs[_REG_RBP as usize]
    )?;
    writeln!(
        writer,
        "rbx: {:#016x}, ",
        mcontext.__gregs[_REG_RBX as usize]
    )?;
    write!(
        writer,
        "rdx: {:#016x}, ",
        mcontext.__gregs[_REG_RDX as usize]
    )?;
    write!(
        writer,
        "rax: {:#016x}, ",
        mcontext.__gregs[_REG_RAX as usize]
    )?;
    write!(
        writer,
        "rcx: {:#016x}, ",
        mcontext.__gregs[_REG_RCX as usize]
    )?;
    writeln!(
        writer,
        "rsp: {:#016x}, ",
        mcontext.__gregs[_REG_RSP as usize]
    )?;
    write!(
        writer,
        "rip: {:#016x}, ",
        mcontext.__gregs[_REG_RIP as usize]
    )?;
    write!(writer, "cs: {:#016x}, ", mcontext.__gregs[_REG_CS as usize])?;
    writeln!(
        writer,
        "rflags: {:#016x}, ",
        mcontext.__gregs[_REG_RFLAGS as usize]
    )?;

    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "openbsd", target_arch = "x86_64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    write!(writer, "r8 : {:#016x}, ", ucontext.sc_r8)?;
    write!(writer, "r9 : {:#016x}, ", ucontext.sc_r9)?;
    write!(writer, "r10 : {:#016x}, ", ucontext.sc_r10)?;
    write!(writer, "r11 : {:#016x}, ", ucontext.sc_r11)?;
    write!(writer, "r12 : {:#016x}, ", ucontext.sc_r12)?;
    write!(writer, "r13 : {:#016x}, ", ucontext.sc_r13)?;
    write!(writer, "r14 : {:#016x}, ", ucontext.sc_r14)?;
    write!(writer, "r15 : {:#016x}, ", ucontext.sc_r15)?;
    write!(writer, "rdi : {:#016x}, ", ucontext.sc_rdi)?;
    write!(writer, "rsi : {:#016x}, ", ucontext.sc_rsi)?;
    write!(writer, "rbp : {:#016x}, ", ucontext.sc_rbp)?;
    write!(writer, "rbx : {:#016x}, ", ucontext.sc_rbx)?;
    write!(writer, "rdx : {:#016x}, ", ucontext.sc_rdx)?;
    write!(writer, "rax : {:#016x}, ", ucontext.sc_rax)?;
    write!(writer, "rcx : {:#016x}, ", ucontext.sc_rcx)?;
    write!(writer, "rsp : {:#016x}, ", ucontext.sc_rsp)?;
    write!(writer, "rflags : {:#016x}, ", ucontext.sc_rflags)?;
    write!(writer, "cs : {:#016x}, ", ucontext.sc_cs)?;
    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "openbsd", target_arch = "aarch64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    for reg in 0..29_usize {
        write!(writer, "x{:02}: 0x{:016x} ", reg, ucontext.sc_x[reg])?;
        if reg % 4 == 3 {
            writeln!(writer)?;
        }
    }
    write!(writer, "lr : {:#016x}, ", ucontext.sc_lr)?;
    write!(writer, "elr : {:#016x}, ", ucontext.sc_elr)?;
    write!(writer, "sp : {:#016x}, ", ucontext.sc_sp)?;
    write!(writer, "spsr : {:#016x}, ", ucontext.sc_spsr)?;
}

///
/// Write the content of all important registers
#[cfg(all(
    any(target_os = "solaris", target_os = "illumos"),
    target_arch = "x86_64"
))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    use libc::{
        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_RAX, REG_RBP,
        REG_RBX, REG_RCX, REG_RDI, REG_RDX, REG_RFL, REG_RIP, REG_RSI, REG_RSP,
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
    writeln!(writer, "efl: {:#016x}, ", mcontext.gregs[REG_RFL as usize])?;

    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    context: &CONTEXT,
) -> Result<(), std::io::Error> {
    write!(writer, "r8 : {:#018x}, ", context.R8)?;
    write!(writer, "r9 : {:#018x}, ", context.R9)?;
    write!(writer, "r10: {:#018x}, ", context.R10)?;
    writeln!(writer, "r11: {:#018x}, ", context.R11)?;
    write!(writer, "r12: {:#018x}, ", context.R12)?;
    write!(writer, "r13: {:#018x}, ", context.R13)?;
    write!(writer, "r14: {:#018x}, ", context.R14)?;
    writeln!(writer, "r15: {:#018x}, ", context.R15)?;
    write!(writer, "rdi: {:#018x}, ", context.Rdi)?;
    write!(writer, "rsi: {:#018x}, ", context.Rsi)?;
    write!(writer, "rbp: {:#018x}, ", context.Rbp)?;
    writeln!(writer, "rbx: {:#018x}, ", context.Rbx)?;
    write!(writer, "rdx: {:#018x}, ", context.Rdx)?;
    write!(writer, "rax: {:#018x}, ", context.Rax)?;
    write!(writer, "rcx: {:#018x}, ", context.Rcx)?;
    writeln!(writer, "rsp: {:#018x}, ", context.Rsp)?;
    write!(writer, "rip: {:#018x}, ", context.Rip)?;
    writeln!(writer, "efl: {:#018x}", context.EFlags)?;

    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    context: &CONTEXT,
) -> Result<(), std::io::Error> {
    write!(writer, "eax: {:#010x}, ", context.Eax)?;
    write!(writer, "ebx: {:#010x}, ", context.Ebx)?;
    write!(writer, "ecx: {:#010x}, ", context.Ecx)?;
    writeln!(writer, "edx: {:#010x}, ", context.Edx)?;
    write!(writer, "edi: {:#010x}, ", context.Edi)?;
    write!(writer, "esi: {:#010x}, ", context.Esi)?;
    write!(writer, "esp: {:#010x}, ", context.Esp)?;
    writeln!(writer, "ebp: {:#010x}, ", context.Ebp)?;
    write!(writer, "eip: {:#010x}, ", context.Eip)?;
    writeln!(writer, "efl: {:#010x} ", context.EFlags)?;
    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    context: &CONTEXT,
) -> Result<(), std::io::Error> {
    for reg in 0..29_usize {
        write!(writer, "x{:02}: 0x{:016x} ", reg, unsafe {
            context.Anonymous.X[reg]
        })?;
        if reg % 4 == 3 || reg == 28_usize {
            writeln!(writer)?;
        }
    }
    writeln!(writer, "pc : 0x{:016x} ", context.Pc)?;
    writeln!(writer, "sp : 0x{:016x} ", context.Sp)?;
    writeln!(writer, "fp : 0x{:016x} ", unsafe {
        context.Anonymous.Anonymous.Fp
    })?;
    writeln!(writer, "lr : 0x{:016x} ", unsafe {
        context.Anonymous.Anonymous.Lr
    })?;

    Ok(())
}

/// Write the content of all important registers
#[cfg(all(target_os = "haiku", target_arch = "x86_64"))]
pub fn dump_registers<W: Write>(
    writer: &mut BufWriter<W>,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    let mcontext = &ucontext.uc_mcontext;

    write!(writer, "r8 : {:#016x}, ", mcontext.r8)?;
    write!(writer, "r9 : {:#016x}, ", mcontext.r9)?;
    write!(writer, "r10 : {:#016x}, ", mcontext.r10)?;
    write!(writer, "r11 : {:#016x}, ", mcontext.r11)?;
    write!(writer, "r12 : {:#016x}, ", mcontext.r12)?;
    write!(writer, "r13 : {:#016x}, ", mcontext.r13)?;
    write!(writer, "r14 : {:#016x}, ", mcontext.r14)?;
    write!(writer, "r15 : {:#016x}, ", mcontext.r15)?;
    write!(writer, "rdi : {:#016x}, ", mcontext.rdi)?;
    write!(writer, "rsi : {:#016x}, ", mcontext.rsi)?;
    write!(writer, "rbp : {:#016x}, ", mcontext.rbp)?;
    write!(writer, "rbx : {:#016x}, ", mcontext.rbx)?;
    write!(writer, "rdx : {:#016x}, ", mcontext.rdx)?;
    write!(writer, "rax : {:#016x}, ", mcontext.rax)?;
    write!(writer, "rcx : {:#016x}, ", mcontext.rcx)?;
    write!(writer, "rsp : {:#016x}, ", mcontext.rsp)?;
    write!(writer, "rflags : {:#016x}, ", mcontext.rflags)?;
    Ok(())
}

#[expect(clippy::unnecessary_wraps)]
#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    windows,
    target_os = "haiku",
    any(target_os = "solaris", target_os = "illumos"),
)))]
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

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "x86_64"
))]
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

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:#08x}, fault address: {:#08x}",
        signal,
        ucontext.uc_mcontext.gregs[libc::REG_EIP as usize],
        ucontext.uc_mcontext.cr2
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

#[cfg(all(target_os = "freebsd", target_arch = "aarch64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at 0x{:016x}",
        signal, ucontext.uc_mcontext.mc_gpregs.gp_elr
    )?;

    Ok(())
}

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
unsafe fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    if ucontext.uc_mcontext.is_null() || !ucontext.uc_mcontext.is_aligned() {
        writeln!(
            writer,
            "Received signal {signal} (null or unaligned uc_mcontext)"
        )?;
        return Ok(());
    }
    let mcontext = unsafe { &*ucontext.uc_mcontext };
    writeln!(
        writer,
        "Received signal {} at 0x{:016x}, fault address: 0x{:016x}",
        signal, mcontext.__ss.__pc, mcontext.__es.__far
    )?;

    Ok(())
}

#[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
unsafe fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    if ucontext.uc_mcontext.is_null() || !ucontext.uc_mcontext.is_aligned() {
        writeln!(
            writer,
            "Received signal {signal} (null or unaligned uc_mcontext)"
        )?;
        return Ok(());
    }
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

#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:016x}, fault address: 0x{:016x}",
        signal, ucontext.uc_mcontext.mc_rip, ucontext.uc_mcontext.mc_fs
    )?;

    Ok(())
}

#[cfg(all(target_os = "freebsd", target_arch = "x86"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:016x}",
        signal, ucontext.uc_mcontext.mc_eip
    )?;

    Ok(())
}

#[cfg(all(target_os = "dragonfly", target_arch = "x86_64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:016x}, fault address: 0x{:016x}",
        signal, ucontext.uc_mcontext.mc_rip, ucontext.uc_mcontext.mc_cs
    )?;

    Ok(())
}

#[cfg(all(target_os = "openbsd", target_arch = "x86_64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:016x}, fault address: 0x{:016x}",
        signal, ucontext.sc_rip, ucontext.sc_fs
    )?;

    Ok(())
}

#[cfg(all(target_os = "openbsd", target_arch = "aarch64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:016x}",
        signal, ucontext.sc_elr
    )?;

    Ok(())
}

#[cfg(all(target_os = "netbsd", target_arch = "x86_64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:#016x}, fault address: {:#016x}",
        signal, ucontext.uc_mcontext.__gregs[21], ucontext.uc_mcontext.__gregs[16]
    )?;

    Ok(())
}

#[cfg(all(
    any(target_os = "solaris", target_os = "illumos"),
    target_arch = "x86_64"
))]
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
        ucontext.uc_mcontext.gregs[libc::REG_FS as usize]
    )?;

    Ok(())
}

#[cfg(all(target_os = "haiku", target_arch = "x86_64"))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    writeln!(
        writer,
        "Received signal {} at {:#016x}",
        signal, ucontext.uc_mcontext.rip
    )?;

    Ok(())
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    windows,
    target_os = "haiku",
    any(target_os = "solaris", target_os = "illumos"),
)))]
fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    _ucontext: &ucontext_t,
) -> Result<(), std::io::Error> {
    // TODO add fault addr for other platforms.
    writeln!(writer, "Received signal {signal}")?;

    Ok(())
}

#[cfg(windows)]
unsafe fn write_crash<W: Write>(
    writer: &mut BufWriter<W>,
    exception_pointers: *mut EXCEPTION_POINTERS,
) -> Result<(), std::io::Error> {
    if exception_pointers.is_null() || !exception_pointers.is_aligned() {
        writeln!(
            writer,
            "Received exception (null or unaligned EXCEPTION_POINTERS)"
        )?;
        return Ok(());
    }
    let rec_ptr = unsafe { (*exception_pointers).ExceptionRecord };
    let record_opt = if rec_ptr.is_aligned() {
        unsafe { rec_ptr.as_ref() }
    } else {
        None
    };
    if let Some(record) = record_opt {
        writeln!(
            writer,
            "Received exception {:0x} at address {:x}",
            record.ExceptionCode.0, record.ExceptionAddress as usize
        )?;
    } else {
        writeln!(writer, "Received exception (null ExceptionRecord)")?;
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn write_minibsod<W: Write>(writer: &mut BufWriter<W>) -> Result<(), std::io::Error> {
    match std::fs::read_to_string("/proc/self/maps") {
        Ok(maps) => writer.write_all(maps.as_bytes())?,
        Err(e) => writeln!(writer, "Couldn't load mappings: {e:?}")?,
    }

    Ok(())
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn write_minibsod<W: Write>(writer: &mut BufWriter<W>) -> Result<(), std::io::Error> {
    let mut s: usize = 0;
    #[cfg(target_os = "freebsd")]
    let arr = &[libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_VMMAP, -1];
    #[cfg(target_os = "netbsd")]
    let arr = &[
        libc::CTL_VM,
        libc::VM_PROC,
        libc::VM_PROC_MAP,
        -1,
        size_of::<libc::kinfo_vmentry>()
            .try_into()
            .expect("Invalid libc::kinfo_vmentry size"),
    ];
    let mib = arr.as_ptr();
    let miblen = arr.len() as u32;
    if unsafe {
        libc::sysctl(
            mib,
            miblen,
            core::ptr::null_mut(),
            &mut s,
            core::ptr::null_mut(),
            0,
        )
    } == 0
    {
        s = s.saturating_add(s / 3);
        let mut buf: alloc::boxed::Box<[u8]> = vec![0; s].into_boxed_slice();
        let bufptr = buf.as_mut_ptr().cast::<libc::c_void>();
        if unsafe { libc::sysctl(mib, miblen, bufptr, &mut s, core::ptr::null_mut(), 0) } == 0 {
            let valid_len = s.min(buf.len());
            let path_off = core::mem::offset_of!(libc::kinfo_vmentry, kve_path);
            let start_off = core::mem::offset_of!(libc::kinfo_vmentry, kve_start);
            let end_off = core::mem::offset_of!(libc::kinfo_vmentry, kve_end);
            let mut offset = 0usize;

            while offset
                .checked_add(path_off)
                .is_some_and(|end| end <= valid_len)
            {
                #[cfg(target_os = "freebsd")]
                let Ok(sz) = ({
                    let sz_off = core::mem::offset_of!(libc::kinfo_vmentry, kve_structsize);
                    let raw: [u8; size_of::<libc::c_int>()] = buf
                        [offset + sz_off..offset + sz_off + size_of::<libc::c_int>()]
                        .try_into()
                        .unwrap();
                    usize::try_from(libc::c_int::from_ne_bytes(raw))
                }) else {
                    break;
                };
                #[cfg(target_os = "netbsd")]
                let sz = size_of::<libc::kinfo_vmentry>();
                let Some(next) = offset
                    .checked_add(sz)
                    .filter(|&n| sz >= path_off && n <= valid_len)
                else {
                    break;
                };
                let entry = &buf[offset..next];
                let start = u64::from_ne_bytes(entry[start_off..start_off + 8].try_into().unwrap());
                let end = u64::from_ne_bytes(entry[end_off..end_off + 8].try_into().unwrap());
                let path_bytes = &entry[path_off..];
                let path = core::ffi::CStr::from_bytes_until_nul(path_bytes).map_or_else(
                    |_| String::from_utf8_lossy(path_bytes),
                    core::ffi::CStr::to_string_lossy,
                );
                writeln!(writer, "{start}-{end} {path:?}")?;
                offset = next;
            }
        } else {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(target_os = "openbsd")]
fn write_minibsod<W: Write>(writer: &mut BufWriter<W>) -> Result<(), std::io::Error> {
    let mut pentry = core::mem::MaybeUninit::<libc::kinfo_vmentry>::zeroed();
    let mut s = size_of::<libc::kinfo_vmentry>();
    let arr = &[libc::CTL_KERN, libc::KERN_PROC_VMMAP, unsafe {
        libc::getpid()
    }];
    let mib = arr.as_ptr();
    let miblen = arr.len() as u32;
    if unsafe {
        libc::sysctl(
            mib,
            miblen,
            pentry.as_mut_ptr() as *mut libc::c_void,
            &mut s,
            core::ptr::null_mut(),
            0,
        )
    } == 0
    {
        let end: u64 = s as u64;
        unsafe {
            let mut e = pentry.assume_init();
            while libc::sysctl(
                mib,
                miblen,
                &mut e as *mut libc::kinfo_vmentry as *mut libc::c_void,
                &mut s,
                core::ptr::null_mut(),
                0,
            ) == 0
            {
                if e.kve_end == end {
                    break;
                }
                // OpenBSD's vm mappings have no knowledge of their paths on disk
                let i = format!("{}-{}\n", e.kve_start, e.kve_end);
                writer.write_all(&i.into_bytes())?;
                e.kve_start += 1;
            }
        }
    } else {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(target_vendor = "apple")]
fn write_minibsod<W: Write>(writer: &mut BufWriter<W>) -> Result<(), std::io::Error> {
    let task = unsafe { mach_task_self() };
    let mut addr: mach_vm_address_t = 0;
    let mut cnt: mach_msg_type_number_t;
    let mut sz: mach_vm_size_t = 0;
    let mut reg: natural_t = 1;

    loop {
        let mut pvminfo = core::mem::MaybeUninit::<vm_region_submap_info_64>::zeroed();
        cnt = mach_msg_type_number_t::try_from(
            size_of::<vm_region_submap_info_64>() / size_of::<natural_t>(),
        )
        .unwrap();
        let r = unsafe {
            mach_vm_region_recurse(
                task,
                &raw mut addr,
                &raw mut sz,
                &raw mut reg,
                pvminfo.as_mut_ptr() as vm_region_recurse_info_t,
                &raw mut cnt,
            )
        };
        if r != libc::KERN_SUCCESS {
            break;
        }
        let Some(next) = addr.checked_add(sz).filter(|&n| n > addr) else {
            break;
        };

        let vminfo = unsafe { pvminfo.assume_init() };
        if vminfo.is_submap == 0 {
            writeln!(writer, "{addr}-{next}")?;
        }
        addr = next;
    }

    Ok(())
}

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
fn write_minibsod<W: Write>(writer: &mut BufWriter<W>) -> Result<(), std::io::Error> {
    let pid = format!("{}", unsafe { libc::getpid() });
    let mut cmdname = Command::new("pmap");
    let cmd = cmdname.args(["-x", &pid]);

    match cmd.output() {
        Ok(s) => writer.write_all(&s.stdout)?,
        Err(e) => writeln!(writer, "Couldn't load mappings: {e:?}")?,
    }

    Ok(())
}

#[cfg(target_os = "haiku")]
fn write_minibsod<W: Write>(writer: &mut BufWriter<W>) -> Result<(), std::io::Error> {
    let mut p = core::mem::MaybeUninit::<libc::image_info>::zeroed();
    let mut c: i32 = 0;

    // Avoid `assume_init_ref`: `libc::image_info` contains non-nullable `fn()` fields that Haiku sets to NULL.
    while unsafe { libc::get_next_image_info(0, &mut c, p.as_mut_ptr()) } == libc::B_OK {
        let ptr = p.as_ptr();
        let (text, size, name) = unsafe {
            (
                (*ptr).text as usize,
                (*ptr).text_size.max(0) as usize,
                &(*ptr).name,
            )
        };
        writeln!(writer, "{text}-{} {name:?}", text.saturating_add(size))?;
    }

    Ok(())
}

#[cfg(not(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "haiku",
    target_vendor = "apple",
    any(target_os = "linux", target_os = "android"),
    any(target_os = "solaris", target_os = "illumos"),
)))]
fn write_minibsod<W: Write>(writer: &mut BufWriter<W>) -> Result<(), std::io::Error> {
    // TODO for other platforms
    writeln!(writer, "{:━^100}", " / ")?;
    Ok(())
}

/// Collapses generic argument lists (`Foo<...>`) in the `Debug` output of a
/// captured [`std::backtrace::Backtrace`] so that deeply-monomorphized frames
/// (as produced by `LibAFL`'s heavily-generic types) stay readable instead of
/// spanning thousands of characters each.
#[cfg(any(unix, windows))]
fn shorten_backtrace(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_ident = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        // Only collapse a `<...>` that is a generic argument list, i.e. one that
        // directly follows an identifier. A `<` preceded by anything else is the
        // start of a `<Type as Trait>` qualified path, which we keep so its
        // structure (and any nested `Ident<...>`) is still readable.
        if c == '<' && prev_ident {
            let mut depth = 1usize;
            for c in chars.by_ref() {
                match c {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            out.push_str("<...>");
            prev_ident = false;
            continue;
        }
        prev_ident = c.is_alphanumeric() || c == '_';
        out.push(c);
    }
    out
}

/// Generates a mini-BSOD given a signal and context.
///
/// # Safety
/// If `ucontext` is `Some`, any target-specific raw pointers inside `ucontext` (such as
/// `uc_mcontext` on Apple platforms) that are non-null and aligned must point to valid,
/// initialized machine context records for the duration of this call.
#[cfg(unix)]
#[allow(clippy::non_ascii_literal)]
pub unsafe fn generate_minibsod<W: Write>(
    writer: &mut BufWriter<W>,
    signal: Signal,
    _siginfo: &siginfo_t,
    ucontext: Option<&ucontext_t>,
) -> Result<(), std::io::Error> {
    writeln!(writer, "{:━^100}", " CRASH ")?;
    if let Some(uctx) = ucontext {
        #[cfg(target_vendor = "apple")]
        unsafe {
            write_crash(writer, signal, uctx)?;
        }
        #[cfg(not(target_vendor = "apple"))]
        write_crash(writer, signal, uctx)?;

        #[cfg(target_pointer_width = "64")]
        {
            writeln!(writer, "{:━^100}", " REGISTERS ")?;
            #[cfg(target_vendor = "apple")]
            if let Err(err) = unsafe { dump_registers(writer, uctx) } {
                if err.kind() == std::io::ErrorKind::InvalidInput {
                    writeln!(writer, "{err}")?;
                } else {
                    return Err(err);
                }
            }
            #[cfg(not(target_vendor = "apple"))]
            dump_registers(writer, uctx)?;
        }
    } else {
        writeln!(writer, "Received signal {signal}")?;
    }
    writeln!(writer, "{:━^100}", " BACKTRACE ")?;
    let backtrace = std::backtrace::Backtrace::force_capture();
    writeln!(writer, "{}", shorten_backtrace(&format!("{backtrace:?}")))?;
    writeln!(writer, "{:━^100}", " MAPS ")?;
    write_minibsod(writer)
}

/// Generates a mini-BSOD given a signal and context and dump it to a [`Vec`]
///
/// # Safety
/// Same safety requirements as [`generate_minibsod`].
#[cfg(unix)]
pub unsafe fn generate_minibsod_to_vec(
    signal: Signal,
    siginfo: &siginfo_t,
    ucontext: Option<&ucontext_t>,
) -> Result<Vec<u8>, std::io::Error> {
    let mut bsod = Vec::new();
    {
        let mut writer = BufWriter::new(&mut bsod);

        unsafe { generate_minibsod(&mut writer, signal, siginfo, ucontext)? };

        writer.flush()?;
    }
    Ok(bsod)
}

/// Generates a mini-BSOD given an `EXCEPTION_POINTERS` structure.
///
/// # Safety
/// If `exception_pointers` is non-null, it must point to a valid `EXCEPTION_POINTERS` instance
/// whose non-null `ExceptionRecord` and `ContextRecord` fields point to valid OS records.
#[cfg(windows)]
#[allow(clippy::non_ascii_literal)]
pub unsafe fn generate_minibsod<W: Write>(
    writer: &mut BufWriter<W>,
    exception_pointers: *mut EXCEPTION_POINTERS,
) -> Result<(), std::io::Error> {
    writeln!(writer, "{:━^100}", " CRASH ")?;
    unsafe { write_crash(writer, exception_pointers)? };
    writeln!(writer, "{:━^100}", " REGISTERS ")?;
    if !exception_pointers.is_null()
        && exception_pointers.is_aligned()
        && let ctx_ptr = unsafe { (*exception_pointers).ContextRecord }
        && ctx_ptr.is_aligned()
        && let Some(ctx) = unsafe { ctx_ptr.as_ref() }
    {
        dump_registers(writer, ctx)?;
    } else {
        writeln!(writer, "ContextRecord is null or unaligned")?;
    }
    writeln!(writer, "{:━^100}", " BACKTRACE ")?;
    let backtrace = std::backtrace::Backtrace::force_capture();
    writeln!(writer, "{}", shorten_backtrace(&format!("{backtrace:?}")))?;
    writeln!(writer, "{:━^100}", " MAPS ")?;
    write_minibsod(writer)
}

#[cfg(unix)]
#[cfg(test)]
mod tests {

    use std::io::{BufWriter, stdout};

    use exceptional::unix_signals::Signal;
    #[cfg(not(target_vendor = "apple"))]
    use exceptional::unix_signals::ucontext;
    #[cfg(target_vendor = "apple")]
    use exceptional::unix_signals::ucontext_t;

    use crate::{dump_registers, generate_minibsod_to_vec};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_dump_registers() {
        let mut writer = BufWriter::new(stdout());
        #[cfg(target_vendor = "apple")]
        {
            let mut uctx: ucontext_t = unsafe { core::mem::zeroed() };
            assert!(unsafe { dump_registers(&mut writer, &uctx) }.is_err());
            #[cfg(target_arch = "aarch64")]
            let mut mctx: exceptional::unix_signals::mcontext64 = unsafe { core::mem::zeroed() };
            #[cfg(target_arch = "x86_64")]
            let mut mctx: libc::__darwin_mcontext64 = unsafe { core::mem::zeroed() };
            uctx.uc_mcontext = &raw mut mctx;
            unsafe { dump_registers(&mut writer, &uctx) }.unwrap();
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let ucontext = ucontext().unwrap();
            dump_registers(&mut writer, &ucontext).unwrap();
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_generate_minibsod_to_vec() {
        #[cfg(target_vendor = "apple")]
        let uctx: ucontext_t = unsafe { core::mem::zeroed() };
        #[cfg(not(target_vendor = "apple"))]
        let uctx = ucontext().unwrap();
        let siginfo: libc::siginfo_t = unsafe { core::mem::zeroed() };
        let bytes = unsafe {
            generate_minibsod_to_vec(Signal::SigSegmentationFault, &siginfo, Some(&uctx))
        }
        .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("CRASH") && text.contains("BACKTRACE") && text.contains("MAPS"));

        let bytes_no_ctx =
            unsafe { generate_minibsod_to_vec(Signal::SigAbort, &siginfo, None) }.unwrap();
        assert!(String::from_utf8_lossy(&bytes_no_ctx).contains("Received signal SIGABRT"));
    }
}

#[cfg(windows)]
#[cfg(test)]
mod tests {

    use std::{
        io::{BufWriter, stdout},
        os::raw::c_void,
        sync::mpsc,
    };

    use windows::Win32::{
        Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE},
        System::{
            Diagnostics::Debug::{
                CONTEXT, CONTEXT_FULL_AMD64, CONTEXT_FULL_ARM64, CONTEXT_FULL_X86, GetThreadContext,
            },
            Threading::{GetCurrentProcess, GetCurrentThread, ResumeThread, SuspendThread},
        },
    };

    use crate::dump_registers;

    #[derive(Default)]
    #[repr(align(16))]
    struct Align16 {
        pub ctx: CONTEXT,
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_dump_registers() {
        let (tx, rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();
        let t = std::thread::spawn(move || {
            let cur = unsafe { GetCurrentThread() };
            let proc = unsafe { GetCurrentProcess() };
            let mut out = HANDLE::default();
            unsafe {
                DuplicateHandle(
                    proc,
                    cur,
                    proc,
                    &raw mut out,
                    0,
                    true,
                    DUPLICATE_SAME_ACCESS,
                )
                .unwrap();
            };
            tx.send(out.0 as i64).unwrap();
            evt_rx.recv().unwrap();
        });

        let thread = rx.recv().unwrap();
        let thread = HANDLE(thread as *mut c_void);
        eprintln!("thread: {thread:?}");
        unsafe { SuspendThread(thread) };

        // https://stackoverflow.com/questions/56516445/getting-0x3e6-when-calling-getthreadcontext-for-debugged-thread
        let mut c = Align16::default();
        if cfg!(target_arch = "x86") {
            c.ctx.ContextFlags = CONTEXT_FULL_X86;
        } else if cfg!(target_arch = "x86_64") {
            c.ctx.ContextFlags = CONTEXT_FULL_AMD64;
        } else if cfg!(target_arch = "aarch64") {
            c.ctx.ContextFlags = CONTEXT_FULL_ARM64;
        }
        unsafe { GetThreadContext(thread, &raw mut (c.ctx)).unwrap() };

        let mut writer = BufWriter::new(stdout());
        dump_registers(&mut writer, &c.ctx).unwrap();

        unsafe { ResumeThread(thread) };
        unsafe { CloseHandle(thread).unwrap() };
        evt_tx.send(true).unwrap();
        t.join().unwrap();
    }
}

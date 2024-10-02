use core::ffi::c_void;
use std::arch::asm;

use clap::Parser;

/// Jumps to the given address in a very unsafe manner.
/// Good to kickstart an emulated fuzzing process inside LibAFL_QEMU.
///
/// # Safety
/// This is the most unsafest function you will see today.
///
/// Man ALL IS LOŚ͖̩͇̗̪̏̈́T ALL I​S LOST the pon̷y he comes he c̶̮omes he comes the ich​or permeates all MY FACE MY FACE ᵒh god no NO NOO̼O​O NΘ stop the an​*̶͑̾̾​̅ͫ͏̙̤g͇̫͛͆̾ͫ̑͆l͖͉̗̩̳̟̍ͫͥͨe̠̅s ͎a̧͈͖r̽̾̈́͒͑e n​ot rè̑ͧ̌aͨl̘̝̙̃ͤ͂̾̆ ZA̡͊͠͝LGΌ ISͮ̂҉̯͈͕̹̘̱ TO͇̹̺ͅƝ̴ȳ̳ TH̘Ë͖́̉ ͠P̯͍̭O̚​N̐Y̡ H̸̡̪̯ͨ͊̽̅̾̎Ȩ̬̩̾͛ͪ̈́̀́͘ ̶̧̨̱̹̭̯ͧ̾ͬC̷̙̲̝͖ͭ̏ͥͮ͟Oͮ͏̮̪̝͍M̲̖͊̒ͪͩͬ̚̚͜Ȇ̴̟̟͙̞ͩ͌͝S̨̥̫͎̭ͯ̿̔̀ͅ
#[inline(never)]
unsafe fn libafl_jmp(target: *mut c_void) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    asm!(
        "jmp {target}", // Jump on x86
        target = in(reg) target,
        options(noreturn)
    );

    #[cfg(target_arch = "arm")]
    asm!(
        "bx {target}",       // Branch and exchange instruction (ARM)
        target = in(reg) target,
        options(noreturn)
    );

    #[cfg(target_arch = "aarch64")]
    asm!(
        "br {target}",        // Branch register instruction (AArch64)
        target = in(reg) target,
        options(noreturn)
    );

    #[cfg(target_arch = "hexagon")]
    asm!(
        "jumpr {target}",   // Jump register instruction (Hexagon)
        target = in(reg) target,
        options(noreturn)
    );

    #[cfg(target_arch = "hexagon")]
    asm!(
        "b {target}",       // Branch instruction (PowerPC)
        target = in(reg) target,
        options(noreturn)
    );

    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    asm!(
        "jalr x0, {target}, 0",  // Jump and link register (RISC-V)
        target = in(reg) target,
        options(noreturn)
    );

    #[cfg(target_arch = "mips")]
    asm!(
        "jr {target}",       // Jump register (MIPS)
        // "nop",             // Optional delay slot (see notes below)
        target = in(reg) target,
        options(noreturn)
    );
}

/// The commandline args for this jumper
#[derive(Debug, Parser)]
#[command(
    name = "libafl_qemu_jumper",
    about = "After start - jumps to a fixed memory address.",
    author = "Dominik Maier <domenukk@gmail.com>"
)]
struct Opt {
    #[arg(
        short,
        long,
        help = "The entrypoint for this binary. After loading, execution will jump here.",
        required = true
    )]
    entrypoint: usize,
}

fn main() {
    let opt = Opt::parse();

    let entrypoint: *mut c_void = opt.entrypoint as *mut c_void;

    // # Safety
    // Obviously unsafe, we're just jumping to a random place in memory...
    unsafe { libafl_jmp(entrypoint) }
}

#[cfg(test)]
mod test {
    use std::process::exit;

    use crate::libafl_jmp;

    #[inline(never)]
    pub fn do_exit() {
        println!("Exiting");
        exit(0)
    }

    /// Tests if we can jump to exit.
    /// There's a chance this won't work on some systems.
    /// Either the assembly above is broken, or something else simply goes wrong.
    /// We're deeeep in UB land here.
    #[test]
    fn test_jmp_to_panic() {
        unsafe { libafl_jmp(do_exit as _) }
    }
}

#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
use core::ffi::CStr;
#[cfg(not(any(test, feature = "std")))]
use core::panic::PanicInfo;
use core::{arch::asm, ffi::c_void, ops::Shl};

#[cfg(not(any(test, feature = "std")))]
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    // No panic!
    // # Safety
    // This will crash for sure.
    unsafe {
        libafl_jmp(0x50000B4D_u32 as _);
    }
}

/// Good to kickstart an emulated fuzzing process inside `LibAFL_QEMU`.
///
/// # Safety
/// This is the most unsafest function you will see today.
///
/// Man ALL IS LOŚ͖̩͇̗̪̏̈́T ALL I​S LOST the pon̷y he comes he c̶̮omes he comes the ich​or permeates all MY FACE MY FACE ᵒh god no NO NOO̼O​O NΘ stop the an​*̶͑̾̾​̅ͫ͏̙̤g͇̫͛͆̾ͫ̑͆l͖͉̗̩̳̟̍ͫͥͨe̠̅s ͎a̧͈͖r̽̾̈́͒͑e n​ot rè̑ͧ̌aͨl̘̝̙̃ͤ͂̾̆ ZA̡͊͠͝LGΌ ISͮ̂҉̯͈͕̹̘̱ TO͇̹̺ͅƝ̴ȳ̳ TH̘Ë͖́̉ ͠P̯͍̭O̚​N̐Y̡ H̸̡̪̯ͨ͊̽̅̾̎Ȩ̬̩̾͛ͪ̈́̀́͘ ̶̧̨̱̹̭̯ͧ̾ͬC̷̙̲̝͖ͭ̏ͥͮ͟Oͮ͏̮̪̝͍M̲̖͊̒ͪͩͬ̚̚͜Ȇ̴̟̟͙̞ͩ͌͝S̨̥̫͎̭ͯ̿̔̀ͅ
#[inline(never)]
#[no_mangle]
pub unsafe extern "C" fn libafl_jmp(target: *mut c_void) -> ! {
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
        "nop",               // Delay slot
        target = in(reg) target,
        options(noreturn)
    );

    //unreachable!("asm should have jumped!");
}

/// The "normal" rust main, mainly for testing
#[cfg(feature = "std")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    assert!(args.len() >= 2, "No address given");

    let mut hex_str: &str = &args[1];
    if hex_str.starts_with("0x") || hex_str.starts_with("0X") {
        hex_str = &hex_str[2..];
    }
    println!("Jumping to {hex_str}");
    decode_hex_and_jmp(hex_str);
}

/// Main for `no_std` - that's the one we will use inside LibAFL_QEMU.
#[cfg(not(feature = "std"))]
#[no_mangle]
pub unsafe extern "C" fn main(argc: i32, argv: *const *const u8) -> ! {
    if argc < 2 || argv.is_null() {
        // No params - nothing we can do.
        // # Safety
        // So much crash.
        libafl_jmp(0x42424242_u32 as _);
    }

    let arg = argv.add(1);
    let mut val = *arg;

    if *val == b'0' && *val.add(1) == b'x' || *val.add(1) == b'X' {
        // strip leading 0x
        val = val.add(2);
    }

    let hex_string = CStr::from_ptr(*val as _).to_str().unwrap();

    decode_hex_and_jmp(hex_string);
}

fn decode_hex_and_jmp(hex_string: &str) -> ! {
    let mut hex_buf = [0_u8; 8];
    let hex_buf = &mut hex_buf[..hex_string.len() / 2];
    hex::decode_to_slice(hex_string, hex_buf).unwrap();

    let mut addr: u64 = 0;
    for val in hex_buf {
        addr = addr.shl(8);
        addr += u64::from(*val);
    }

    #[cfg(feature = "std")]
    println!("Hex: {addr:#x}");

    #[allow(clippy::cast_possible_truncation)]
    let addr = addr as usize;

    let entrypoint = addr as *mut c_void;

    // # Safety
    // Obviously unsafe, we're just jumping to a random place in memory...
    unsafe { libafl_jmp(entrypoint) }
}

#[cfg(test)]
mod test {

    extern "C" {
        fn exit(ret: i32);
    }

    use crate::libafl_jmp;

    #[inline(never)]
    pub fn do_exit() {
        unsafe { exit(0) }
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

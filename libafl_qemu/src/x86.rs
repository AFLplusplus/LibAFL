use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(IntoPrimitive, TryFromPrimitive, Clone, Copy)]
#[repr(i32)]
#[allow(clippy::pub_enum_variant_names)]
pub enum X86Regs {
    Eax = 0,
    Ebx = 1,
    Ecx = 2,
    Edx = 3,
    Esi = 4,
    Edi = 5,
    Ebp = 6,
    Esp = 7,
    Eip = 8,
    Eflags = 9,
}

use libafl::{
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_qemu::{ArchExtras, CallingConvention, GuestAddr, GuestReg, MmapPerms, Qemu, Regs};

pub struct Harness<'a> {
    qemu: &'a Qemu,
    input_addr: GuestAddr,
    pc: GuestAddr,
    stack_ptr: GuestAddr,
    ret_addr: GuestAddr,
}

pub const MAX_INPUT_SIZE: usize = 1_048_576; // 1MB

impl<'a> Harness<'a> {
    pub fn new(qemu: &Qemu) -> Result<Harness, Error> {
        let input_addr = qemu
            .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
            .map_err(|e| Error::unknown(format!("Failed to map input buffer: {e:}")))?;

        let pc: GuestReg = qemu
            .read_reg(Regs::Pc)
            .map_err(|e| Error::unknown(format!("Failed to read PC: {e:}")))?;

        let stack_ptr: GuestAddr = qemu
            .read_reg(Regs::Sp)
            .map_err(|e| Error::unknown(format!("Failed to read stack pointer: {e:}")))?;

        let ret_addr: GuestAddr = qemu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:}")))?;

        Ok(Harness {
            qemu,
            input_addr,
            pc,
            stack_ptr,
            ret_addr,
        })
    }

    pub fn run(&self, input: &BytesInput) -> ExitKind {
        self.reset(input).unwrap();
        ExitKind::Ok
    }

    fn reset(&self, input: &BytesInput) -> Result<(), Error> {
        let target = input.target_bytes();
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > MAX_INPUT_SIZE {
            buf = &buf[0..MAX_INPUT_SIZE];
            len = MAX_INPUT_SIZE;
        }
        let len = len as GuestReg;

        unsafe { self.qemu.write_mem(self.input_addr, buf) };

        self.qemu
            .write_reg(Regs::Pc, self.pc)
            .map_err(|e| Error::unknown(format!("Failed to write PC: {e:}")))?;

        self.qemu
            .write_reg(Regs::Sp, self.stack_ptr)
            .map_err(|e| Error::unknown(format!("Failed to write SP: {e:}")))?;

        self.qemu
            .write_return_address(self.ret_addr)
            .map_err(|e| Error::unknown(format!("Failed to write return address: {e:}")))?;

        self.qemu
            .write_function_argument(CallingConvention::Cdecl, 0, self.input_addr)
            .map_err(|e| Error::unknown(format!("Failed to write argument 0: {e:}")))?;

        self.qemu
            .write_function_argument(CallingConvention::Cdecl, 1, len)
            .map_err(|e| Error::unknown(format!("Failed to write argument 1: {e:}")))?;
        unsafe {
            let _ = self.qemu.run();
        };
        Ok(())
    }
}

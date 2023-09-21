use {
    libafl::{
        executors::ExitKind,
        inputs::{BytesInput, HasTargetBytes},
        Error,
    },
    libafl_bolts::AsSlice,
    libafl_qemu::{ArchExtras, CallingConvention, Emulator, GuestAddr, GuestReg, MmapPerms, Regs},
};

pub struct Harness<'a> {
    emu: &'a Emulator,
    input_addr: GuestAddr,
    pc: GuestAddr,
    stack_ptr: GuestAddr,
    ret_addr: GuestAddr,
}

impl<'a> Harness<'a> {
    pub fn new(emu: &Emulator) -> Result<Harness, Error> {
        let input_addr = emu
            .map_private(0, 4096, MmapPerms::ReadWrite)
            .map_err(|e| Error::unknown(format!("Failed to map input buffer: {e:}")))?;

        let pc: GuestReg = emu
            .read_reg(Regs::Pc)
            .map_err(|e| Error::unknown(format!("Failed to read PC: {e:}")))?;

        let stack_ptr: GuestAddr = emu
            .read_reg(Regs::Sp)
            .map_err(|e| Error::unknown(format!("Failed to read stack pointer: {e:}")))?;

        let ret_addr: GuestAddr = emu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:}")))?;

        Ok(Harness {
            emu,
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
        let buf = target
            .as_slice()
            .chunks(4096)
            .next()
            .ok_or_else(|| Error::unknown(format!("Failed to read input buffer")))?;
        let len = buf.len() as GuestReg;

        unsafe { self.emu.write_mem(self.input_addr, buf) };

        self.emu
            .write_reg(Regs::Pc, self.pc)
            .map_err(|e| Error::unknown(format!("Failed to write PC: {e:}")))?;

        self.emu
            .write_reg(Regs::Sp, self.stack_ptr)
            .map_err(|e| Error::unknown(format!("Failed to write SP: {e:}")))?;

        self.emu
            .write_return_address(self.ret_addr)
            .map_err(|e| Error::unknown(format!("Failed to write return address: {e:}")))?;

        self.emu
            .write_function_argument(CallingConvention::Cdecl, 0, self.input_addr)
            .map_err(|e| Error::unknown(format!("Failed to write argument 0: {e:}")))?;

        self.emu
            .write_function_argument(CallingConvention::Cdecl, 1, len)
            .map_err(|e| Error::unknown(format!("Failed to write argument 1: {e:}")))?;
        unsafe { self.emu.run() };
        Ok(())
    }
}

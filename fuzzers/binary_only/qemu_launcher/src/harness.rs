use libafl::{
    executors::ExitKind,
    inputs::{BytesInput, HasTargetBytes},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_qemu::{elf::EasyElf, ArchExtras, GuestAddr, GuestReg, MmapPerms, Qemu, Regs};

pub struct Harness {
    qemu: Qemu,
    input_addr: GuestAddr,
    pc: GuestAddr,
    stack_ptr: GuestAddr,
    ret_addr: GuestAddr,
}

pub const MAX_INPUT_SIZE: usize = 1_048_576; // 1MB

impl Harness {
    /// Change environment
    #[inline]
    #[expect(clippy::ptr_arg)]
    pub fn edit_env(_env: &mut Vec<(String, String)>) {}

    /// Change arguments
    #[inline]
    #[expect(clippy::ptr_arg)]
    pub fn edit_args(_args: &mut Vec<String>) {}

    /// Helper function to find the function we want to fuzz.
    fn start_pc(qemu: Qemu) -> Result<GuestAddr, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;

        let start_pc = elf
            .resolve_symbol("LLVMFuzzerTestOneInput", qemu.load_addr())
            .ok_or_else(|| Error::empty_optional("Symbol LLVMFuzzerTestOneInput not found"))?;
        Ok(start_pc)
    }

    /// Initialize the emulator, run to the entrypoint (or jump there) and return the [`Harness`] struct
    pub fn init(qemu: Qemu) -> Result<Harness, Error> {
        let start_pc = Self::start_pc(qemu)?;
        log::info!("start_pc @ {start_pc:#x}");

        qemu.entry_break(start_pc);

        let ret_addr: GuestAddr = qemu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:?}")))?;
        log::info!("ret_addr = {ret_addr:#x}");
        qemu.set_breakpoint(ret_addr);

        let input_addr = qemu
            .map_private(0, MAX_INPUT_SIZE, MmapPerms::ReadWrite)
            .map_err(|e| Error::unknown(format!("Failed to map input buffer: {e:}")))?;

        let pc: GuestReg = qemu
            .read_reg(Regs::Pc)
            .map_err(|e| Error::unknown(format!("Failed to read PC: {e:?}")))?;

        let stack_ptr: GuestAddr = qemu
            .read_reg(Regs::Sp)
            .map_err(|e| Error::unknown(format!("Failed to read stack pointer: {e:?}")))?;

        let ret_addr: GuestAddr = qemu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:?}")))?;

        Ok(Harness {
            qemu,
            input_addr,
            pc,
            stack_ptr,
            ret_addr,
        })
    }

    /// If we need to do extra work after forking, we can do that here.
    #[inline]
    #[expect(clippy::unused_self)]
    pub fn post_fork(&self) {}

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

        self.qemu.write_mem(self.input_addr, buf).map_err(|e| {
            Error::unknown(format!(
                "Failed to write to memory@{:#x}: {e:?}",
                self.input_addr
            ))
        })?;

        self.qemu
            .write_reg(Regs::Pc, self.pc)
            .map_err(|e| Error::unknown(format!("Failed to write PC: {e:?}")))?;

        self.qemu
            .write_reg(Regs::Sp, self.stack_ptr)
            .map_err(|e| Error::unknown(format!("Failed to write SP: {e:?}")))?;

        self.qemu
            .write_return_address(self.ret_addr)
            .map_err(|e| Error::unknown(format!("Failed to write return address: {e:?}")))?;

        self.qemu
            .write_function_argument(0, self.input_addr)
            .map_err(|e| Error::unknown(format!("Failed to write argument 0: {e:?}")))?;

        self.qemu
            .write_function_argument(1, len)
            .map_err(|e| Error::unknown(format!("Failed to write argument 1: {e:?}")))?;
        unsafe {
            let _ = self.qemu.run();
        };
        Ok(())
    }
}

use std::{fs::File, io::Read};

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
pub use libafl_targets::{edges_max_num, EDGES_MAP, EDGES_MAP_PTR, EDGES_MAP_SIZE, MAX_EDGES_NUM};
use unicorn_engine::{
    unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Permission},
    RegisterARM, RegisterARM64, RegisterX86, Unicorn,
};

pub static CODE_ADDRESS: u64 = 0x9000;
static HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

use crate::{helper::get_stack_pointer, hooks::block_hook};

pub struct Emulator {
    emu: unicorn_engine::Unicorn<'static, ()>,
    code_len: u64,
}

impl Emulator {
    pub fn new(arch: Arch) -> Emulator {
        let emu = unicorn_engine::Unicorn::new(
            arch,
            match arch {
                Arch::ARM => Mode::ARM,
                Arch::ARM64 => Mode::ARM,
                Arch::X86 => Mode::MODE_64,
                _ => Mode::MODE_64,
            },
        )
        .expect("failed to initialize Unicorn instance");
        Emulator { emu, code_len: 0 }
    }

    pub fn setup(&mut self, input_addr: u64, input_size: usize, code_path: &str) {
        self.code_len = load_code(&mut self.emu, CODE_ADDRESS, code_path);
        // TODO: For some reason, the compiled program start by substracting 0x10 to SP
        self.emu
            .mem_map(input_addr, input_size, Permission::WRITE | Permission::READ)
            .expect("failed to map data page");
    }

    pub fn get_code_len(&self) -> u64 {
        self.code_len
    }

    pub fn write_mem(&mut self, addr: u64, buf: &[u8]) {
        //println!("{} -> {}", addr, addr + (buf.len() as u64));
        self.emu
            .mem_write(addr, &buf)
            .expect("failed to write instructions");
    }

    pub fn set_memory_hook<F: 'static>(&mut self, addr: u64, length: usize, callback: F)
    where
        F: FnMut(&mut Unicorn<()>, MemType, u64, usize, i64) -> bool,
    {
        self.emu
            .add_mem_hook(HookType::MEM_ALL, addr, addr + length as u64, callback)
            .expect("Could not set memory hooks");
    }

    pub fn set_code_hook(&mut self) {
        self.emu
            .add_block_hook(block_hook)
            .expect("Failed to register code hook");
    }

    pub fn reg_write<T>(&mut self, regid: T, value: u64)
    where
        T: Into<i32>,
    {
        self.emu
            .reg_write(regid, value)
            .expect("Could not set registry");
    }

    pub fn reg_read<T>(&self, regid: T) -> Result<u64, uc_error>
    where
        T: Into<i32>,
    {
        self.emu.reg_read(regid)
    }

    pub fn init_registers(&mut self, sp: u64) {
        match self.emu.get_arch() {
            Arch::ARM => {
                self.emu
                    .reg_write(RegisterARM::SP, sp)
                    .expect("Could not setup register");
            }
            Arch::ARM64 => {
                self.emu
                    .reg_write(RegisterARM64::SP, sp)
                    .expect("Could not setup register");
            }
            Arch::X86 => {
                // clean emulator state
                for i in 1..259 {
                    self.emu.reg_write(i, 0).expect("Could not clean register");
                }

                self.emu
                    .reg_write(RegisterX86::ESP, sp)
                    .expect("Could not setup register");
            }
            _ => {}
        }
    }

    pub fn mem_read(&self, address: u64, buf: &mut [u8]) -> Result<(), uc_error> {
        self.emu.mem_read(address, buf)
    }

    pub fn get_stack_pointer(&mut self) -> u64 {
        get_stack_pointer(&mut self.emu)
    }

    pub fn pc_read(&self) -> Result<u64, uc_error> {
        self.emu.pc_read()
    }

    pub fn get_arch(&self) -> Arch {
        return self.emu.get_arch();
    }

    pub fn memory_dump(&mut self, len: u64) {
        let sp = get_stack_pointer(&mut self.emu);
        for i in 0..len {
            let pos = sp + i * 4 - len * 4;

            let data = self.emu.mem_read_as_vec(pos, 4).unwrap();

            println!(
                "{:X}:\t {:02X} {:02X} {:02X} {:02X}  {:08b} {:08b} {:08b} {:08b}",
                pos, data[0], data[1], data[2], data[3], data[0], data[1], data[2], data[3]
            );
        }
    }

    pub fn emu_start(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
    ) -> Result<(), uc_error> {
        self.emu.emu_start(begin, until, timeout, count)
    }

    pub fn debug_print(&self, err: uc_error) {
        println!();
        println!("Snap... something went wrong");
        println!("Error: {:?}", err);

        let pc = self.emu.pc_read().unwrap();
        println!();
        println!("Status when crash happened");

        println!("PC: {:X}", pc);
        let arch = self.emu.get_arch();

        match arch {
            Arch::ARM => {
                println!("SP: {:X}", self.emu.reg_read(RegisterARM::SP).unwrap());
            }
            Arch::ARM64 => {
                println!("SP: {:X}", self.emu.reg_read(RegisterARM64::SP).unwrap());
                println!("X0: {:X}", self.emu.reg_read(RegisterARM64::X0).unwrap());
                println!("X1: {:X}", self.emu.reg_read(RegisterARM64::X1).unwrap());
                println!("X2: {:X}", self.emu.reg_read(RegisterARM64::X2).unwrap());
                println!("X3: {:X}", self.emu.reg_read(RegisterARM64::X3).unwrap());
            }
            Arch::X86 => {
                println!("ESP: {:X}", self.emu.reg_read(RegisterX86::ESP).unwrap());
                println!("RAX: {:X}", self.emu.reg_read(RegisterX86::RAX).unwrap());
                println!("RCX: {:X}", self.emu.reg_read(RegisterX86::RCX).unwrap());
                println!("RPB: {:X}", self.emu.reg_read(RegisterX86::RBP).unwrap());
                println!("RSP: {:X}", self.emu.reg_read(RegisterX86::RSP).unwrap());
                println!("EAX: {:X}", self.emu.reg_read(RegisterX86::EAX).unwrap());
                println!("ECX: {:X}", self.emu.reg_read(RegisterX86::ECX).unwrap());
                println!("EDX: {:X}", self.emu.reg_read(RegisterX86::EDX).unwrap());
            }
            _ => {}
        }

        if self.emu.get_arch() == Arch::X86 {
            // Provide dissasembly at instant of crash for X86 assembly
            let regions = self
                .emu
                .mem_regions()
                .expect("Could not get memory regions");
            for i in 0..regions.len() {
                if regions[i].perms == Permission::EXEC {
                    if pc >= regions[i].begin && pc <= regions[i].end {
                        let mut begin = pc - 32;
                        let mut end = pc + 32;
                        if begin < regions[i].begin {
                            begin = regions[i].begin;
                        }
                        if end > regions[i].end {
                            end = regions[i].end;
                        }

                        let bytes = self
                            .emu
                            .mem_read_as_vec(begin, (end - begin) as usize)
                            .expect("Could not get program code");

                        let mut decoder = Decoder::with_ip(64, &bytes, begin, DecoderOptions::NONE);

                        let mut formatter = NasmFormatter::new();
                        formatter.options_mut().set_digit_separator("`");
                        formatter.options_mut().set_first_operand_char_index(10);

                        let mut instruction = Instruction::default();
                        let mut output = String::new();

                        while decoder.can_decode() {
                            decoder.decode_out(&mut instruction);

                            // Format the instruction ("disassemble" it)
                            output.clear();
                            formatter.format(&instruction, &mut output);

                            let diff = instruction.ip() as i64 - pc as i64;
                            print!("{:02}\t{:016X} ", diff, instruction.ip());
                            let start_index = (instruction.ip() - begin) as usize;
                            let instr_bytes = &bytes[start_index..start_index + instruction.len()];
                            for b in instr_bytes.iter() {
                                print!("{:02X}", b);
                            }
                            if instr_bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
                                for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - instr_bytes.len() {
                                    print!("  ");
                                }
                            }
                            println!(" {}", output);
                        }
                    }
                }
            }
        }
    }
}

fn load_code(emu: &mut Unicorn<()>, address: u64, path: &str) -> u64 {
    let mut f = File::open(path).expect("Could not open file");
    let mut buffer = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer).expect("Could not read file");

    let arm_code = buffer;

    // Define memory regions
    emu.mem_map(
        address,
        match emu.get_arch() {
            Arch::ARM => ((arm_code.len() / 1024) + 1) * 1024,
            Arch::ARM64 => ((arm_code.len() / 1024) + 1) * 1024,
            Arch::X86 => ((arm_code.len() / 4096) + 1) * 4096,
            _ => 0,
        },
        Permission::EXEC,
    )
    .expect("failed to map code page");

    // Write memory
    emu.mem_write(address, &arm_code)
        .expect("failed to write instructions");
    return arm_code.len() as u64;
}

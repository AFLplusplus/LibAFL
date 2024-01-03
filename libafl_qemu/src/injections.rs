//! Detect injection vulnerabilities

/*
 * TODOs:
 *  - read in export addresses of shared libraries to resolve functions
 *
 * Maybe:
 *  - return code analysis support (not needed currently)
 *  - regex support (not needed currently)
 *  - std::string and Rust String support (would need such target functions added)
 *
 */

#[cfg(emulation_mode = "usermode")]
use std::sync::OnceLock;
use std::{ffi::CStr, fs::File, io::Read, os::raw::c_char, path::Path};

use libafl::{inputs::UsesInput, Error};
use serde::{Deserialize, Serialize};

use crate::{
    elf::EasyElf, Emulator, GuestAddr, Hook, QemuHelper, QemuHelperTuple, QemuHooks, Regs,
    SYS_execve, SyscallHookResult,
};

#[derive(Debug, Clone)]
struct LibInfo {
    name: String,
    off: GuestAddr,
}

impl LibInfo {
    fn add_unique(libs: &mut Vec<LibInfo>, new_lib: LibInfo) {
        if !libs.iter().any(|lib| lib.name == new_lib.name) {
            libs.push(new_lib);
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Test {
    input_value: String,
    match_value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Functions {
    function: String,
    parameter: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct InjectStructure {
    name: String,
    functions: Vec<Functions>,
    tests: Vec<Test>,
}

static INJECTIONS: OnceLock<Vec<InjectStructure>> = OnceLock::new();
pub static TOKENS: OnceLock<Vec<String>> = OnceLock::new();

fn parse_yaml<P: AsRef<Path>>(path: P) -> Result<Vec<InjectStructure>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let data: Vec<InjectStructure> = serde_yaml::from_str(&contents)?;
    Ok(data)
}

#[derive(Debug)]
pub struct QemuInjectionHelper {}

impl Default for QemuInjectionHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl QemuInjectionHelper {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// configure_injections is the main function to activatr the injection
    /// vulnerability detection feature.
    pub fn configure_injections(
        emu: &Emulator,
        yaml_file: &String,
        breakpoint: GuestAddr,
    ) -> Vec<String> {
        let mut injections = parse_yaml(yaml_file).unwrap();
        for injection in &mut injections {
            for test in &mut injection.tests {
                test.match_value = test.match_value.to_lowercase();
            }
        }
        INJECTIONS
            .set(injections)
            .expect("Failed to set injections");
        emu.set_breakpoint(breakpoint);
        let _emu_state = unsafe { emu.run() };
        emu.remove_breakpoint(breakpoint);

        let mut id: u64 = 0;
        let mut tokens: Vec<String> = Vec::new();
        // Initial tokens for syscall command injection detection
        tokens.push("\";FUZZ;\"".to_string());
        tokens.push("';FUZZ;'".to_string());
        tokens.push("$(FUZZ)".to_string());

        let mut libs: Vec<LibInfo> = Vec::new();

        for region in emu.mappings() {
            if let Some(path) = region.path().map(ToOwned::to_owned) {
                if !path.is_empty() {
                    LibInfo::add_unique(
                        &mut libs,
                        LibInfo {
                            name: path.clone(),
                            off: region.start(),
                        },
                    );
                }
            }
        }

        for target in INJECTIONS.get().expect("Could not get injections") {
            for func in &target.functions {
                let mut found = 0;
                if func.function.to_lowercase().starts_with(&"0x".to_string()) {
                    let func_pc = u64::from_str_radix(&func.function[2..], 16)
                        .expect("Failed to parse hex string {func.function} from yaml")
                        as GuestAddr;
                    if func_pc > 0 {
                        println!("Hooking hardcoded function {func_pc:#x}");
                        let data: u64 = (id << 8) + u64::from(func.parameter);
                        let _hook_id = emu.set_hook(data, func_pc, on_call_check, false);
                        found = 1;
                    }
                } else {
                    for lib in &libs {
                        let func_pc = find_function(emu, &lib.name, &func.function, lib.off)
                            .unwrap_or_default();
                        if func_pc > 0 {
                            println!("Function {} found at {func_pc:#x}", func.function);
                            let data: u64 = (id << 8) + u64::from(func.parameter);
                            let _hook_id = emu.set_hook(data, func_pc, on_call_check, false);
                            found = 1;
                        }
                    }
                }
                if found > 0 {
                    for test in &target.tests {
                        tokens.push(test.input_value.clone());
                    }
                } else {
                    println!("Function not found: {}", func.function);
                }
            }
            id += 1;
        }

        TOKENS.set(tokens.clone()).expect("Failed to set tokens");
        tokens
    }
}

impl<S> QemuHelper<S> for QemuInjectionHelper
where
    S: UsesInput,
{
    fn init_hooks<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {
        hooks.syscalls(Hook::Function(syscall_hook::<QT, S>));
    }
}

fn syscall_hook<QT, S>(
    hooks: &mut QemuHooks<QT, S>, // our instantiated QemuHooks
    _state: Option<&mut S>,
    syscall: i32, // syscall number
    x0: u64,      // registers ...
    x1: u64,
    _x2: u64,
    _x3: u64,
    _x4: u64,
    _x5: u64,
    _x6: u64,
    _x7: u64,
) -> SyscallHookResult
where
    QT: QemuHelperTuple<S>,
    S: UsesInput,
{
    //println!("syscall_hook {} {}", syscall, SYS_execve);
    debug_assert!(i32::try_from(SYS_execve).is_ok());
    if syscall == SYS_execve as i32 {
        let _helper = hooks
            .helpers_mut()
            .match_first_type_mut::<QemuInjectionHelper>()
            .unwrap();
        if x0 > 0 && x1 > 0 {
            let c_array = x1 as *const *const c_char;
            let cmd = unsafe {
                let c_str_ptr = x0 as *const c_char;
                CStr::from_ptr(c_str_ptr).to_string_lossy()
            };
            assert!(
                cmd.to_lowercase() != "fuzz",
                "Found verified command injection!"
            );
            //println!("CMD {}", cmd);

            let first_parameter = unsafe {
                if (*c_array.offset(1)).is_null() {
                    return SyscallHookResult::new(None);
                }
                CStr::from_ptr(*c_array.offset(1)).to_string_lossy()
            };
            let second_parameter = unsafe {
                if (*c_array.offset(2)).is_null() {
                    return SyscallHookResult::new(None);
                }
                CStr::from_ptr(*c_array.offset(2)).to_string_lossy()
            };
            if first_parameter == "-c"
                && (second_parameter.to_lowercase().contains("';fuzz;'")
                    || second_parameter.to_lowercase().contains("\";fuzz;\""))
            {
                panic!("Found command injection!");
            }

            //println!("PARAMETERS First {} Second {}", first_parameter, second_
        }
        SyscallHookResult::new(Some(0))
    } else {
        SyscallHookResult::new(None)
    }
}

fn find_function(
    emu: &Emulator,
    file: &String,
    function: &str,
    loadaddr: GuestAddr,
) -> Result<GuestAddr, Error> {
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(file, &mut elf_buffer)?;
    let offset = if loadaddr > 0 {
        loadaddr
    } else {
        emu.load_addr()
    };
    let start_pc = elf
        .resolve_symbol(function, offset)
        .ok_or_else(|| Error::empty_optional("Symbol {function} not found in {file}"))?;
    println!("Found {function} in {file}");
    Ok(start_pc)
}

extern "C" fn on_call_check(val: u64, _pc: GuestAddr) {
    let emu = Emulator::new_empty();
    let parameter: u8 = (val & 0xff) as u8;
    let off: usize = (val >> 8) as usize;

    //println!("on_call_check {} {}", parameter, off);

    #[cfg(any(target_arch = "x86_64", not(target_arch)))]
    let reg: GuestAddr = match parameter {
        0 => emu.current_cpu().unwrap().read_reg(Regs::Rdi).unwrap_or(0),
        1 => emu.current_cpu().unwrap().read_reg(Regs::Rsi).unwrap_or(0),
        2 => emu.current_cpu().unwrap().read_reg(Regs::Rdx).unwrap_or(0),
        3 => emu.current_cpu().unwrap().read_reg(Regs::Rcx).unwrap_or(0),
        4 => emu.current_cpu().unwrap().read_reg(Regs::R8).unwrap_or(0),
        5 => emu.current_cpu().unwrap().read_reg(Regs::R9).unwrap_or(0),
        _ => panic!("unknown register"),
    };
    #[cfg(cpu_target = "aarch64")]
    let reg: GuestAddr = match parameter {
        0 => emu.current_cpu().unwrap().read_reg(Regs::X0).unwrap_or(0),
        1 => emu.current_cpu().unwrap().read_reg(Regs::X1).unwrap_or(0),
        2 => emu.current_cpu().unwrap().read_reg(Regs::X2).unwrap_or(0),
        3 => emu.current_cpu().unwrap().read_reg(Regs::X3).unwrap_or(0),
        4 => emu.current_cpu().unwrap().read_reg(Regs::X4).unwrap_or(0),
        5 => emu.current_cpu().unwrap().read_reg(Regs::X5).unwrap_or(0),
        _ => panic!("unknown register"),
    };
    #[cfg(cpu_target = "arm")]
    let reg: GuestAddr = match parameter {
        0 => emu.current_cpu().unwrap().read_reg(Regs::R0).unwrap_or(0),
        1 => emu.current_cpu().unwrap().read_reg(Regs::R1).unwrap_or(0),
        2 => emu.current_cpu().unwrap().read_reg(Regs::R2).unwrap_or(0),
        3 => emu.current_cpu().unwrap().read_reg(Regs::R3).unwrap_or(0),
        // 4.. would be on the stack, let's not do this for now
        _ => panic!("unknown register"),
    };
    #[cfg(cpu_target = "mips")]
    let reg: GuestAddr = match parameter {
        0 => emu.current_cpu().unwrap().read_reg(Regs::A0).unwrap_or(0),
        1 => emu.current_cpu().unwrap().read_reg(Regs::A1).unwrap_or(0),
        2 => emu.current_cpu().unwrap().read_reg(Regs::A2).unwrap_or(0),
        3 => emu.current_cpu().unwrap().read_reg(Regs::A3).unwrap_or(0),
        // 4.. would be on the stack, let's not do this for now
        _ => panic!("unknown register"),
    };
    #[cfg(cpu_target = "ppc")]
    let reg: GuestAddr = match parameter {
        0 => emu.current_cpu().unwrap().read_reg(Regs::R3).unwrap_or(0),
        1 => emu.current_cpu().unwrap().read_reg(Regs::R4).unwrap_or(0),
        2 => emu.current_cpu().unwrap().read_reg(Regs::R5).unwrap_or(0),
        3 => emu.current_cpu().unwrap().read_reg(Regs::R6).unwrap_or(0),
        4 => emu.current_cpu().unwrap().read_reg(Regs::R7).unwrap_or(0),
        5 => emu.current_cpu().unwrap().read_reg(Regs::R8).unwrap_or(0),
        _ => panic!("unknown register"),
    };
    //i386 is unsupported
    #[cfg(cpu_target = "i386")]
    let reg: GuestAddr = 0;

    //println!("reg value = {:x}", reg);

    if reg > 0 {
        let query = unsafe {
            let c_str_ptr = reg as *const c_char;
            let c_str = CStr::from_ptr(c_str_ptr);
            c_str.to_string_lossy()
        };

        //println!("query={}", query);
        let vec = INJECTIONS.get().unwrap();
        let injection = &vec[off];
        //println!("Checking {}", injection.name);
        for test in &injection.tests {
            if query.to_lowercase().contains(&test.match_value) {
                panic!(
                    "Found value \"{}\" for {} in {}",
                    test.match_value, query, injection.name
                );
            }
        }
    }
}

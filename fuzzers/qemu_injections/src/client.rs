use std::{
    env, ffi::CStr, fs::File, io::Read, ops::Range, os::raw::c_char, path::Path, sync::Mutex,
};

use lazy_static::lazy_static;
use libafl::{
    corpus::{InMemoryOnDiskCorpus, OnDiskCorpus},
    events::LlmpRestartingEventManager,
    inputs::BytesInput,
    prelude::UsesInput,
    state::StdState,
    Error,
};
use libafl_bolts::{
    core_affinity::CoreId, rands::StdRand, shmem::StdShMemProvider, tuples::tuple_list,
};
use libafl_qemu::{
    asan::{init_with_asan, QemuAsanHelper},
    cmplog::QemuCmpLogHelper,
    edges::QemuEdgeCoverageHelper,
    elf::EasyElf,
    ArchExtras, Emulator, GuestAddr, Hook, QemuHelper, QemuHelperTuple, QemuHooks,
    QemuInstrumentationFilter, Regs, SYS_execve, SyscallHookResult,
};
use serde::{Deserialize, Serialize};

use crate::{instance::Instance, options::FuzzerOptions};

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

lazy_static! {
    static ref INJECTIONS: Mutex<Vec<InjectStructure>> = Mutex::new(Vec::new());
    pub static ref TOKENS: Mutex<Vec<String>> = Mutex::new(Vec::new());
}

fn parse_yaml<P: AsRef<Path>>(path: P) -> Result<Vec<InjectStructure>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let data: Vec<InjectStructure> = serde_yaml::from_str(&contents)?;
    Ok(data)
}

#[derive(Default, Debug)]
struct QemuExecSyscallHelper {
    // foo
}

impl QemuExecSyscallHelper {
    fn new() -> Self {
        Self {}
    }
}

impl<S> QemuHelper<S> for QemuExecSyscallHelper
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
            .match_first_type_mut::<QemuExecSyscallHelper>()
            .unwrap();

        if x0 > 0 && x1 > 0 {
            let c_array = x1 as *const *const c_char;
            let cmd = unsafe {
                let c_str_ptr = x0 as *const c_char;
                let c_str = CStr::from_ptr(c_str_ptr);
                c_str.to_string_lossy()
            };

            assert!(
                !(cmd.to_lowercase() == "fuzz"),
                "Found verified command injection!"
            );
            //println!("CMD {}", cmd);

            let first_parameter = unsafe {
                if (*c_array.offset(1)).is_null() {
                    return SyscallHookResult::new(None);
                }
                let c_str = CStr::from_ptr(*c_array.offset(1));
                c_str.to_string_lossy()
            };
            let second_parameter = unsafe {
                if (*c_array.offset(2)).is_null() {
                    return SyscallHookResult::new(None);
                }
                let c_str = CStr::from_ptr(*c_array.offset(2));
                c_str.to_string_lossy()
            };
            if first_parameter == "-c"
                && (second_parameter.to_lowercase().contains("';fuzz;'")
                    || second_parameter.to_lowercase().contains("\";fuzz;\""))
            {
                panic!("Found command injection!");
            }

            //println!("PARAMETERS First {} Second {}", first_parameter, second_parameter);
        }
        SyscallHookResult::new(Some(0))
    } else {
        SyscallHookResult::new(None)
    }
}

pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

pub struct Client<'a> {
    options: &'a FuzzerOptions,
}

impl<'a> Client<'a> {
    pub fn new(options: &FuzzerOptions) -> Client {
        Client { options }
    }

    fn args(&self) -> Result<Vec<String>, Error> {
        let program = env::args()
            .next()
            .ok_or_else(|| Error::empty_optional("Failed to read program name"))?;

        let mut args = self.options.args.clone();
        args.insert(0, program);
        Ok(args)
    }

    fn env() -> Vec<(String, String)> {
        env::vars()
            .filter(|(k, _v)| k != "LD_LIBRARY_PATH")
            .collect::<Vec<(String, String)>>()
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

    fn start_pc(emu: &Emulator) -> Result<GuestAddr, Error> {
        let mut elf_buffer = Vec::new();
        let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;

        let start_pc = elf
            .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
            .ok_or_else(|| Error::empty_optional("Symbol LLVMFuzzerTestOneInput not found"))?;
        Ok(start_pc)
    }

    fn coverage_filter(&self, emu: &Emulator) -> Result<QemuInstrumentationFilter, Error> {
        // Conversion is required on 32-bit targets, but not on 64-bit ones
        if let Some(includes) = &self.options.include {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = includes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(QemuInstrumentationFilter::AllowList(rules))
        } else if let Some(excludes) = &self.options.exclude {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = excludes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(QemuInstrumentationFilter::DenyList(rules))
        } else {
            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;
            let range = elf
                .get_section(".text", emu.load_addr())
                .ok_or_else(|| Error::key_not_found("Failed to find .text section"))?;
            Ok(QemuInstrumentationFilter::AllowList(vec![range]))
        }
    }

    pub fn run(
        &self,
        state: Option<ClientState>,
        mgr: LlmpRestartingEventManager<ClientState, StdShMemProvider>,
        core_id: CoreId,
    ) -> Result<(), Error> {
        let mut args = self.args()?;
        log::debug!("ARGS: {:#?}", args);

        let mut env = Self::env();
        log::debug!("ENV: {:#?}", env);

        let (emu, mut asan) = {
            if self.options.is_asan_core(core_id) {
                let (emu, asan) = init_with_asan(&mut args, &mut env)?;
                (emu, Some(asan))
            } else {
                //eprintln!("Bug is here");
                (Emulator::new(&args, &env)?, None)
            }
        };

        let start_pc = Self::start_pc(&emu)?;
        log::debug!("start_pc @ {start_pc:#x}");

        let injections = parse_yaml(self.options.get_yaml_file()).unwrap();
        let mut vec = INJECTIONS.lock().unwrap();
        *vec = injections.clone();
        drop(vec);

        // Break at the entry point after the loading process
        emu.set_breakpoint(start_pc);
        let _emu_state = unsafe { emu.run() };
        /*
        println!(
            "Entry break at {:#x}",
            emu.read_reg::<_, u64>(Regs::Pc).unwrap()
        );
        */
        emu.remove_breakpoint(start_pc);

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
        //println!("Mappings: {:?}", libs);

        for target in injections {
            for func in target.functions {
                let mut found = 0;
                if func.function.to_lowercase().starts_with(&"0x".to_string()) {
                    let func_pc = u64::from_str_radix(&func.function[2..], 16)
                        .expect("Failed to parse hex string {func.function} from yaml")
                        as GuestAddr;
                    if func_pc > 0 {
                        println!("Hooking hardcoded function {func_pc:#x}");
                        let data: u64 = (id << 8) + u64::from(func.parameter);
                        let _hook_id = emu.set_hook(data, func_pc, Self::on_call_check, false);
                        found = 1;
                    }
                } else {
                    for lib in &libs {
                        let func_pc = Self::find_function(&emu, &lib.name, &func.function, lib.off)
                            .unwrap_or_default();
                        if func_pc > 0 {
                            println!("Function {} found at {func_pc:#x}", func.function);
                            let data: u64 = (id << 8) + u64::from(func.parameter);
                            let _hook_id = emu.set_hook(data, func_pc, Self::on_call_check, false);
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

        let mut vec = TOKENS.lock().unwrap();
        *vec = tokens.clone();
        drop(vec);

        emu.entry_break(start_pc);

        let ret_addr: GuestAddr = emu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("Failed to read return address: {e:}")))?;
        log::debug!("ret_addr = {ret_addr:#x}");
        emu.set_breakpoint(ret_addr);

        let is_asan = self.options.is_asan_core(core_id);
        let is_cmplog = self.options.is_cmplog_core(core_id);

        let edge_coverage_helper = QemuEdgeCoverageHelper::new(self.coverage_filter(&emu)?);

        let instance = Instance::builder()
            .options(self.options)
            .emu(&emu)
            .mgr(mgr)
            .core_id(core_id);
        if is_asan && is_cmplog {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuCmpLogHelper::default(),
                QemuAsanHelper::default(asan.take().unwrap()),
                QemuExecSyscallHelper::new(),
            );
            instance.build().run(helpers, state)
        } else if is_asan {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuAsanHelper::default(asan.take().unwrap()),
                QemuExecSyscallHelper::new(),
            );
            instance.build().run(helpers, state)
        } else if is_cmplog {
            let helpers = tuple_list!(
                edge_coverage_helper,
                QemuCmpLogHelper::default(),
                QemuExecSyscallHelper::new(),
            );
            instance.build().run(helpers, state)
        } else {
            let helpers = tuple_list!(edge_coverage_helper, QemuExecSyscallHelper::new(),);
            instance.build().run(helpers, state)
        }
    }

    extern "C" fn on_call_check(val: u64, _pc: GuestAddr) {
        let emu = Emulator::new_empty();
        let parameter: u8 = (val & 0xff) as u8;
        let off: usize = (val >> 8) as usize;

        //println!("on_call_check {} {}", parameter, off);

        let reg: GuestAddr = match parameter {
            0 => emu.current_cpu().unwrap().read_reg(Regs::Rdi).unwrap_or(0),
            1 => emu.current_cpu().unwrap().read_reg(Regs::Rsi).unwrap_or(0),
            2 => emu.current_cpu().unwrap().read_reg(Regs::Rdx).unwrap_or(0),
            3 => emu.current_cpu().unwrap().read_reg(Regs::Rcx).unwrap_or(0),
            4 => emu.current_cpu().unwrap().read_reg(Regs::R8).unwrap_or(0),
            5 => emu.current_cpu().unwrap().read_reg(Regs::R9).unwrap_or(0),
            _ => panic!("unknown register"),
        };
        //println!("reg value = {:x}", reg);
        if reg > 0 {
            let query = unsafe {
                let c_str_ptr = reg as *const c_char;
                let c_str = CStr::from_ptr(c_str_ptr);
                c_str.to_string_lossy()
            };

            //println!("query={}", query);
            let vec = INJECTIONS.lock().unwrap();
            let injection = &vec[off];
            //println!("Checking {}", injection.name);
            for test in &injection.tests {
                if query
                    .to_lowercase()
                    .contains(&test.match_value.to_lowercase())
                {
                    panic!(
                        "Found value \"{}\" for {} in {}",
                        test.match_value, query, injection.name
                    );
                }
            }
        }
    }
}

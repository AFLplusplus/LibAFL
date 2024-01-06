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

use std::{ffi::CStr, fmt::Display, fs, os::raw::c_char, path::Path, sync::OnceLock};

use hashbrown::HashMap;
use libafl::{inputs::UsesInput, Error};
use serde::{Deserialize, Serialize};

use crate::{
    elf::EasyElf, emu::ArchExtras, CallingConvention, Emulator, GuestAddr, Hook, QemuHelper,
    QemuHelperTuple, QemuHooks, SYS_execve, SyscallHookResult,
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
struct YamlInjectionEntry {
    name: String,
    functions: Vec<Functions>,
    tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
struct FunctionDescription {
    param: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TomlInjectionDefinition {
    tokens: Vec<String>,
    matches: Vec<String>,
    functions: HashMap<String, FunctionDescription>,
}

static INJECTIONS: OnceLock<Vec<YamlInjectionEntry>> = OnceLock::new();
pub static TOKENS: OnceLock<Vec<String>> = OnceLock::new();

fn parse_yaml<P: AsRef<Path> + Display>(path: P) -> Result<Vec<YamlInjectionEntry>, Error> {
    serde_yaml::from_str(&fs::read_to_string(&path)?)
        .map_err(|e| Error::serialize(format!("Failed to deserialize yaml at {path}: {e}")))
}

fn parse_toml<P: AsRef<Path> + Display>(
    path: P,
) -> Result<HashMap<String, TomlInjectionDefinition>, Error> {
    toml::from_str(&fs::read_to_string(&path)?)
        .map_err(|e| Error::serialize(format!("Failed to deserialize toml at {path}: {e}")))
}

fn yaml_entries_to_definition(
    yaml_entries: &Vec<YamlInjectionEntry>,
) -> Result<HashMap<String, TomlInjectionDefinition>, Error> {
    let mut ret = HashMap::new();

    for entry in yaml_entries {
        let mut functions = HashMap::new();
        for function in &entry.functions {
            functions.insert(
                function.function.clone(),
                FunctionDescription {
                    param: function.parameter,
                },
            );
        }

        let mut matches = Vec::new();
        let mut tokens = Vec::new();
        for test in &entry.tests {
            matches.push(test.match_value.clone());
            tokens.push(test.input_value.clone());
        }

        if let Some(_) = ret.insert(
            entry.name.clone(),
            TomlInjectionDefinition {
                tokens,
                matches,
                functions,
            },
        ) {
            return Err(Error::illegal_argument(format!(
                "Entry {} was multiply defined!",
                entry.name
            )));
        }
    }
    Ok(ret)
}


#[derive(Clone, Debug)]
pub struct Match {
    name: String,
    bytes_lower: Vec<u8>,
    original_value: String,
}

#[derive(Debug)]
pub struct QemuInjectionHelper {
    tokens: Vec<String>,
    definitions: HashMap<String, TomlInjectionDefinition>,
}

impl QemuInjectionHelper {
    /// `configure_injections` is the main function to activate the injection
    /// vulnerability detection feature.
    #[must_use]
    pub fn from_yaml<P: AsRef<Path> + Display>(
        emu: &Emulator,
        yaml_file: P,
    ) -> Result<Self, Error> {
        let yaml_entries = parse_yaml(yaml_file)?;
        let definition = yaml_entries_to_definition(&yaml_entries)?;
        Self::new(emu, definition)
    }

    /// `configure_injections` is the main function to activate the injection
    /// vulnerability detection feature.
    #[must_use]
    pub fn from_toml<P: AsRef<Path> + Display>(
        emu: &Emulator,
        toml_file: P,
    ) -> Result<Self, Error> {
        let definition = parse_toml(toml_file)?;
        Self::new(emu, definition)
    }

    pub fn new(
        emu: &Emulator,
        definitions: HashMap<String, TomlInjectionDefinition>,
    ) -> Result<Self, Error> {
        for (lib_name, definition) in definitions.iter() {

        Ok(Self { tokens, definitions })
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

    fn first_exec<QT>(&self, hooks: &QemuHooks<QT, S>)
    where
        QT: QemuHelperTuple<S>,
    {

        let emu = hooks.emulator();

        let mut id: u64 = 0;
        let mut tokens: Vec<String> = Vec::new();
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

        for (lib_name, definition) in definitions.iter() {
            for (name, func_definition) in &definition.functions {
                let mut found = 0;
                if name.to_lowercase().starts_with(&"0x".to_string()) {
                    let func_pc = u64::from_str_radix(&name[2..], 16).map_err(|e| {
                        Error::illegal_argument(format!(
                            "Failed to parse hex string {name} from definition for {lib_name}: {e}"
                        ))
                    })? as GuestAddr;
                    if func_pc > 0 {
                        // println!("Hooking hardcoded function {func_pc:#x}");
                        let data: u64 = (id << 8) + u64::from(func_definition.param);

                        let _hook_id = emu.set_hook(data, func_pc, on_call_check, false);
                        found = 1;
                    }
                } else {
                    for lib in &libs {
                        let func_pc =
                            find_function(emu, &lib.name, &name, lib.off).unwrap_or_default();
                        if func_pc > 0 {
                            //println!("Function {} found at {func_pc:#x}", func.function);
                            hooks.instruction(func_pc, Hook::Closure(on_call_check), false)

                            let data: u64 = (id << 8) + u64::from(func_definition.param);
                            let _hook_id =

                             emu.set_hook(data, func_pc, on_call_check, false);
                            found = 1;
                        }
                    }
                }
                if found > 0 {
                    tokens.append(&mut definition.tokens.clone())
                }
                //else {
                //println!("Function not found: {}", func.function);
                //}
            }
            id += 1;
        }


        hooks.instruction(Hook::Closure(), true)
        addr: GuestAddr,
        hook: Hook<
            fn(&mut Self, Option<&mut S>, GuestAddr),
            Box<dyn for<'a> FnMut(&'a mut Self, Option<&'a mut S>, GuestAddr)>,
            extern "C" fn(*const (), pc: GuestAddr),
        >,
        invalidate_block: bool,



    }
}

fn syscall_hook<QT, S>(
    hooks: &mut QemuHooks<QT, S>, // our instantiated QemuHooks
    _state: Option<&mut S>,
    syscall: i32,  // syscall number
    x0: GuestAddr, // registers ...
    x1: GuestAddr,
    _x2: GuestAddr,
    _x3: GuestAddr,
    _x4: GuestAddr,
    _x5: GuestAddr,
    _x6: GuestAddr,
    _x7: GuestAddr,
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
            assert_ne!(
                cmd.to_lowercase(), "fuzz",
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
        .ok_or_else(|| Error::empty_optional(format!("Symbol {function} not found in {file}")))?;
    println!("Found {function} in {file}");
    Ok(start_pc)
}

fn on_call_check(matches: &Vec<Vec<u8>>, parameter: u8) {
    let emu = Emulator::get().unwrap();

    let reg: GuestAddr = emu
        .current_cpu()
        .unwrap()
        .read_function_argument(CallingConvention::Cdecl, parameter)
        .unwrap_or_default();

    //println!("reg value = {:x}", reg);

    if reg != 0x00 {
        let query = unsafe {
            let c_str_ptr = reg as *const c_char;
            let c_str = CStr::from_ptr(c_str_ptr);
        };

        //println!("query={}", query);
        //println!("Checking {}", injection.name);
        for match in matches.iter() {
            // "crash" if we found the right value
            assert!(
                query.to_lowercase().contains(&test.match_value),
                "Found value \"{}\" for {query} in {}",
                test.match_value,
                query,
                injection.name
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{yaml_entries_to_definition, TomlInjectionDefinition, YamlInjectionEntry};
    use hashbrown::HashMap;

    #[test]
    fn test_yaml_parsing() {
        let injections: Vec<YamlInjectionEntry> = serde_yaml::from_str(
            r#"
            # LDAP injection tests
            - name: "ldap"
              functions:
                - function: "ldap_search_ext"
                  parameter: 3
                - function: "ldap_search_ext_s"
                  parameter: 3
              tests:
                - input_value: "*)(FUZZ=*))(|"
                  match_value: "*)(FUZZ=*))(|"
            
            # XSS injection tests
            # This is a minimal example that only checks for libxml2
            - name: "xss"
              functions:
                - function: "htmlReadMemory"
                  parameter: 0
              tests:
                - input_value: "'\"><FUZZ"
                  match_value: "'\"><FUZZ"
            "#,
        )
        .unwrap();
        assert_eq!(injections.len(), 2);

        assert_eq!(
            injections.len(),
            yaml_entries_to_definition(&injections)
                .unwrap()
                .keys()
                .len(),
        );
    }

    #[test]
    fn test_toml_parsing() {
        let injections: HashMap<String, TomlInjectionDefinition> = toml::from_str(
            r#"
            [ldap]
            tokens = ["*)(FUZZ=*))(|"]
            matches = ["*)(FUZZ=*))(|"]

            [ldap.functions]
            ldap_search_ext = {param = 3}
            ldap_search_ext_s = {param = 3}

            # XSS injection tests
            # This is a minimal example that only checks for libxml2
            [xss]
            tokens = ["'\"><FUZZ"]
            matches = ["'\"><FUZZ"]
            [xss.functions]
            htmlReadMemory = {param = 0}
            "#,
        )
        .unwrap();
        assert_eq!(injections.len(), 2);
    }
}

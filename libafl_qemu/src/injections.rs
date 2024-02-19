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

use std::{ffi::CStr, fmt::Display, fs, os::raw::c_char, path::Path};

use hashbrown::HashMap;
use libafl::{inputs::UsesInput, Error};
use serde::{Deserialize, Serialize};

#[cfg(not(cpu_target = "hexagon"))]
use crate::SYS_execve;
use crate::{
    elf::EasyElf, emu::ArchExtras, CallingConvention, Emulator, GuestAddr, Hook, QemuHelper,
    QemuHelperTuple, QemuHooks, SyscallHookResult,
};
#[cfg(cpu_target = "hexagon")]
/// Hexagon syscalls are not currently supported by the `syscalls` crate, so we just paste this here for now.
/// <https://github.com/qemu/qemu/blob/11be70677c70fdccd452a3233653949b79e97908/linux-user/hexagon/syscall_nr.h#L230>
const SYS_execve: u8 = 221;

/// Parses `injections.yaml`
fn parse_yaml<P: AsRef<Path> + Display>(path: P) -> Result<Vec<YamlInjectionEntry>, Error> {
    serde_yaml::from_str(&fs::read_to_string(&path)?)
        .map_err(|e| Error::serialize(format!("Failed to deserialize yaml at {path}: {e}")))
}

/// Parses `injections.toml`
fn parse_toml<P: AsRef<Path> + Display>(
    path: P,
) -> Result<HashMap<String, InjectionDefinition>, Error> {
    toml::from_str(&fs::read_to_string(&path)?)
        .map_err(|e| Error::serialize(format!("Failed to deserialize toml at {path}: {e}")))
}

/// Converts the injects.yaml format to the internal toml-like format
fn yaml_entries_to_definition(
    yaml_entries: &Vec<YamlInjectionEntry>,
) -> Result<HashMap<String, InjectionDefinition>, Error> {
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

        if ret
            .insert(
                entry.name.clone(),
                InjectionDefinition {
                    tokens,
                    matches,
                    functions,
                },
            )
            .is_some()
        {
            return Err(Error::illegal_argument(format!(
                "Entry {} was multiply defined!",
                entry.name
            )));
        }
    }
    Ok(ret)
}

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
pub struct InjectionDefinition {
    tokens: Vec<String>,
    matches: Vec<String>,
    functions: HashMap<String, FunctionDescription>,
}

#[derive(Clone, Debug)]
pub struct Matches {
    id: usize,
    lib_name: String,
    matches: Vec<Match>,
}

#[derive(Clone, Debug)]
pub struct Match {
    bytes_lower: Vec<u8>,
    original_value: String,
}

#[derive(Debug)]
pub struct QemuInjectionHelper {
    pub tokens: Vec<String>,
    definitions: HashMap<String, InjectionDefinition>,
    matches_list: Vec<Matches>,
}

impl QemuInjectionHelper {
    /// `configure_injections` is the main function to activate the injection
    /// vulnerability detection feature.
    pub fn from_yaml<P: AsRef<Path> + Display>(yaml_file: P) -> Result<Self, Error> {
        let yaml_entries = parse_yaml(yaml_file)?;
        let definition = yaml_entries_to_definition(&yaml_entries)?;
        Self::new(definition)
    }

    /// `configure_injections` is the main function to activate the injection
    /// vulnerability detection feature.
    pub fn from_toml<P: AsRef<Path> + Display>(toml_file: P) -> Result<Self, Error> {
        let definition = parse_toml(toml_file)?;
        Self::new(definition)
    }

    pub fn new(definitions: HashMap<String, InjectionDefinition>) -> Result<Self, Error> {
        let tokens = definitions
            .iter()
            .flat_map(|(_lib_name, definition)| &definition.tokens)
            .map(ToString::to_string)
            .collect();

        let mut matches_list = Vec::with_capacity(definitions.len());

        for (lib_name, definition) in &definitions {
            let matches: Vec<Match> = definition
                .matches
                .iter()
                .map(|match_str| {
                    let mut bytes_lower = match_str.as_bytes().to_vec();
                    bytes_lower.make_ascii_lowercase();

                    Match {
                        original_value: match_str.clone(),
                        bytes_lower,
                    }
                })
                .collect();

            let id = matches_list.len();
            matches_list.push(Matches {
                lib_name: lib_name.clone(),
                id,
                matches,
            });
        }

        Ok(Self {
            tokens,
            definitions,
            matches_list,
        })
    }

    fn on_call_check<S: UsesInput, QT: QemuHelperTuple<S>>(
        hooks: &mut QemuHooks<QT, S>,
        id: usize,
        parameter: u8,
    ) {
        let emu = hooks.emulator();
        let reg: GuestAddr = emu
            .current_cpu()
            .unwrap()
            .read_function_argument(CallingConvention::Cdecl, parameter)
            .unwrap_or_default();

        let helper = hooks.helpers_mut().match_first_type_mut::<Self>().unwrap();
        let matches = &helper.matches_list[id];

        //println!("reg value = {:x}", reg);

        if reg != 0x00 {
            let mut query = unsafe {
                let c_str_ptr = reg as *const c_char;
                let c_str = CStr::from_ptr(c_str_ptr);
                c_str.to_bytes().to_vec()
            };
            query.make_ascii_lowercase();

            //println!("query={}", query);
            log::trace!("Checking {}", matches.lib_name);

            for match_value in &matches.matches {
                if match_value.bytes_lower.len() > matches.matches.len() {
                    continue;
                }

                // "crash" if we found the right value
                assert!(
                    find_subsequence(&query, &match_value.bytes_lower).is_none(),
                    "Found value \"{}\" for {query:?} in {}",
                    match_value.original_value,
                    matches.lib_name
                );
            }
        }
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

        for matches in &self.matches_list {
            let id = matches.id;
            let lib_name = &matches.lib_name;

            for (name, func_definition) in &self.definitions[lib_name].functions {
                let hook_addrs = if name.to_lowercase().starts_with(&"0x".to_string()) {
                    let func_pc = u64::from_str_radix(&name[2..], 16)
                        .map_err(|e| {
                            Error::illegal_argument(format!(
                            "Failed to parse hex string {name} from definition for {lib_name}: {e}"
                        ))
                        })
                        .unwrap() as GuestAddr;
                    log::info!("Injections: Hooking hardcoded function {func_pc:#x}");
                    vec![func_pc]
                } else {
                    libs.iter()
                        .filter_map(|lib| find_function(emu, &lib.name, name, lib.off).unwrap())
                        .map(|func_pc| {
                            log::info!("Injections: Function {name} found at {func_pc:#x}",);
                            func_pc
                        })
                        .collect()
                };

                if hook_addrs.is_empty() {
                    log::warn!("Injections: Function not found for {lib_name}: {name}",);
                }

                let param = func_definition.param;

                for hook_addr in hook_addrs {
                    hooks.instruction(
                        hook_addr,
                        Hook::Closure(Box::new(move |hooks, _state, _guest_addr| {
                            Self::on_call_check(hooks, id, param);
                        })),
                        true,
                    );
                }
            }
        }
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
    log::trace!("syscall_hook {syscall} {SYS_execve}");
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
                cmd.to_lowercase(),
                "fuzz",
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
    file: &str,
    function: &str,
    loadaddr: GuestAddr,
) -> Result<Option<GuestAddr>, Error> {
    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(file, &mut elf_buffer)?;
    let offset = if loadaddr > 0 {
        loadaddr
    } else {
        emu.load_addr()
    };
    Ok(elf.resolve_symbol(function, offset))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    use super::{yaml_entries_to_definition, InjectionDefinition, YamlInjectionEntry};

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
        let injections: HashMap<String, InjectionDefinition> = toml::from_str(
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

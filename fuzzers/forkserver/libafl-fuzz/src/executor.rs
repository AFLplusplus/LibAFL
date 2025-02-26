use std::{
    fs::File,
    marker::PhantomData,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use libafl::{
    executors::{Executor, ExitKind, HasObservers, HasTimeout},
    state::HasCorpus,
    Error,
};
use libafl_bolts::tuples::RefIndexable;
use memmap2::{Mmap, MmapOptions};
use nix::libc::{S_IRUSR, S_IXUSR};

use crate::{Opt, DEFER_SIG, PERSIST_SIG};

const AFL_PATH: &str = "/usr/local/lib/afl/";
const BIN_PATH: &str = "/usr/local/bin/";

// TODO better error messages and logging
pub fn check_binary(opt: &mut Opt, shmem_env_var: &str) -> Result<(), Error> {
    println!("Validating target binary...");

    let bin_path;
    // check if it is a file path
    if opt.executable.components().count() == 1 {
        // check $PATH for the binary.
        if let Some(full_bin_path) = find_executable_in_path(&opt.executable) {
            opt.executable = full_bin_path;
            bin_path = &opt.executable;
        } else {
            return Err(Error::illegal_argument(format!(
                "Program '{}' not found or not executable",
                opt.executable.display()
            )));
        }
    } else {
        bin_path = &opt.executable;
        #[cfg(feature = "nyx")]
        {
            if opt.nyx_mode {
                if !bin_path.is_symlink() && bin_path.is_dir() {
                    let config_file = bin_path.join("config.ron");
                    if !config_file.is_symlink() && config_file.is_file() {
                        return Ok(());
                    }
                }
                return Err(Error::illegal_argument(
                    format!(
                        "Directory '{}' not found, or is a symlink or is not a nyx share directory",
                        bin_path.display()
                    )
                    .as_str(),
                ));
            }
        }
    }
    let metadata = bin_path.metadata()?;
    // AFL++ does not follow symlinks, BUT we do.
    let is_reg = bin_path.is_file();
    let bin_size = metadata.len();
    let is_executable = metadata.permissions().mode() & 0o111 != 0;
    if !is_reg || !is_executable || bin_size < 4 {
        return Err(Error::illegal_argument(format!(
            "Program '{}' not found or not executable",
            bin_path.display()
        )));
    }
    if opt.skip_bin_check
        || opt.wine_mode
        || opt.unicorn_mode
        || (opt.qemu_mode && opt.qemu_custom_bin)
        || (opt.forkserver_cs && opt.cs_custom_bin)
        || opt.non_instrumented_mode
    {
        return Ok(());
    }

    let file = File::open(bin_path)?;
    let mmap = unsafe { MmapOptions::new().map(&file)? };

    // check if it's a shell script
    if mmap[0..1] == [0x43, 0x41] {
        // TODO: finish error message
        return Err(Error::illegal_argument(
            "Oops, the target binary looks like a shell script.",
        ));
    }

    // check if the binary is an ELF file
    #[cfg(feature = "nyx")]
    if mmap[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        return Err(Error::illegal_argument(format!(
            "Program '{}' is not an ELF binary",
            bin_path.display()
        )));
    }

    #[cfg(target_vendor = "apple")]
    {
        if (mmap[0] != 0xCF || mmap[1] != 0xFA || mmap[2] != 0xED)
            && (mmap[0] != 0xCA || mmap[1] != 0xFE || mmap[2] != 0xBA)
        {
            return Err(Error::illegal_argument(format!(
                "Program '{}' is not a 64-bit or universal Mach-O binary",
                bin_path.display()
            )));
        }
    }

    let check_instrumentation = !opt.qemu_mode
        && !opt.frida_mode
        && !opt.unicorn_mode
        && !opt.forkserver_cs
        && !opt.non_instrumented_mode;

    #[cfg(feature = "nyx")]
    let check_instrumentation = check_instrumentation && !opt.nyx_mode;

    if check_instrumentation && !is_instrumented(&mmap, shmem_env_var) {
        return Err(Error::illegal_argument(
            "target binary is not instrumented correctly",
        ));
    }

    if (opt.forkserver_cs || opt.qemu_mode || opt.frida_mode)
        && is_instrumented(&mmap, shmem_env_var)
    {
        return Err(Error::illegal_argument(
            "Instrumentation found in -Q/-O mode",
        ));
    }

    if mmap_has_substr(&mmap, "__asan_init")
        || mmap_has_substr(&mmap, "__lsan_init")
        || mmap_has_substr(&mmap, "__lsan_init")
    {
        opt.uses_asan = true;
    }

    if mmap_has_substr(&mmap, PERSIST_SIG) {
        opt.is_persistent = true;
    } else if opt.is_persistent {
        println!("persistent mode enforced");
    } else if opt.frida_persistent_addr.is_some() {
        opt.is_persistent = true;
        opt.defer_forkserver = true;
        println!("FRIDA persistent mode configuration options detected");
    }

    if opt.frida_mode || mmap_has_substr(&mmap, DEFER_SIG) {
        println!("deferred forkserver binary detected");
        opt.defer_forkserver = true;
    } else if opt.defer_forkserver {
        println!("defer forkserver enforced");
    }

    Ok(())
    // Safety: unmap() is called on Mmap object Drop
}

fn mmap_has_substr(mmap: &Mmap, sub_str: &str) -> bool {
    let mmap_len = mmap.len();
    let substr_len = sub_str.len();
    if mmap_len < substr_len {
        return false;
    }
    for i in 0..(mmap_len - substr_len) {
        if &mmap[i..i + substr_len] == sub_str.as_bytes() {
            return true;
        }
    }
    false
}

fn is_instrumented(mmap: &Mmap, shmem_env_var: &str) -> bool {
    mmap_has_substr(mmap, shmem_env_var)
}

fn find_executable_in_path<P: AsRef<Path>>(executable: &P) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full_path = dir.join(executable);
            if full_path.is_file() {
                Some(full_path)
            } else {
                None
            }
        })
    })
}

pub fn find_afl_binary(filename: &str, same_dir_as: Option<PathBuf>) -> Result<PathBuf, Error> {
    let extension = Path::new(filename).extension();
    let is_library = if let Some(extension) = extension {
        extension.eq_ignore_ascii_case("so") || extension.eq_ignore_ascii_case("dylib")
    } else {
        false
    };

    #[allow(clippy::useless_conversion)] // u16 on MacOS, u32 on Linux
    let permission = if is_library {
        u32::from(S_IRUSR) // user can read
    } else {
        u32::from(S_IXUSR) // user can exec
    };

    // First we check if it is present in AFL_PATH
    if let Ok(afl_path) = std::env::var("AFL_PATH") {
        let file = PathBuf::from(afl_path).join(filename);
        if check_file_found(&file, permission) {
            return Ok(file);
        }
    }

    // next we check the same directory as the provided parameter
    if let Some(same_dir_as) = same_dir_as {
        if let Some(parent_dir) = same_dir_as.parent() {
            let file = parent_dir.join(filename);
            if check_file_found(&file, permission) {
                return Ok(file);
            }
        }
    }

    // check sensible defaults
    let file = PathBuf::from(if is_library { AFL_PATH } else { BIN_PATH }).join(filename);
    let found = check_file_found(&file, permission);
    if found {
        return Ok(file);
    }

    if !is_library {
        // finally, check the path for the binary
        return find_executable_in_path(&filename)
            .ok_or(Error::unknown(format!("cannot find {filename}")));
    }

    Err(Error::unknown(format!("cannot find {filename}")))
}

fn check_file_found(file: &Path, perm: u32) -> bool {
    if !file.exists() {
        return false;
    }
    if let Ok(metadata) = file.metadata() {
        return metadata.permissions().mode() & perm != 0;
    }
    false
}

#[cfg(feature = "nyx")]
pub enum SupportedExecutors<FSV, I, OT, NYX> {
    Forkserver(FSV, PhantomData<(FSV, I, OT)>),
    Nyx(NYX),
}

#[cfg(feature = "nyx")]
impl<S, I, OT, FSV, NYX, EM, Z> Executor<EM, I, S, Z> for SupportedExecutors<FSV, I, OT, NYX>
where
    NYX: Executor<EM, I, S, Z>,
    FSV: Executor<EM, I, S, Z>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.run_target(fuzzer, state, mgr, input),
            #[cfg(feature = "nyx")]
            Self::Nyx(nyx) => nyx.run_target(fuzzer, state, mgr, input),
        }
    }
}

#[cfg(feature = "nyx")]
impl<FSV, I, OT, NYX> HasObservers for SupportedExecutors<FSV, I, OT, NYX>
where
    NYX: HasObservers<Observers = OT>,
    FSV: HasObservers<Observers = OT>,
{
    type Observers = OT;
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.observers(),
            #[cfg(feature = "nyx")]
            Self::Nyx(nyx) => nyx.observers(),
        }
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.observers_mut(),
            #[cfg(feature = "nyx")]
            Self::Nyx(nyx) => nyx.observers_mut(),
        }
    }
}

#[cfg(feature = "nyx")]
impl<FSV, I, OT, NYX> HasTimeout for SupportedExecutors<FSV, I, OT, NYX>
where
    FSV: HasTimeout,
    NYX: HasTimeout,
{
    fn set_timeout(&mut self, timeout: std::time::Duration) {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.set_timeout(timeout),
            #[cfg(feature = "nyx")]
            Self::Nyx(nyx) => nyx.set_timeout(timeout),
        }
    }
    fn timeout(&self) -> std::time::Duration {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.timeout(),
            #[cfg(feature = "nyx")]
            Self::Nyx(nyx) => nyx.timeout(),
        }
    }
}

#[cfg(not(feature = "nyx"))]
pub enum SupportedExecutors<FSV, I, OT, S> {
    Forkserver(FSV, PhantomData<(I, OT, S)>),
}

#[cfg(not(feature = "nyx"))]
impl<S, I, OT, FSV, EM, Z> Executor<EM, I, S, Z> for SupportedExecutors<FSV, I, OT, S>
where
    S: HasCorpus<I>,
    FSV: Executor<EM, I, S, Z>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.run_target(fuzzer, state, mgr, input),
        }
    }
}

#[cfg(not(feature = "nyx"))]
impl<FSV, I, OT, S> HasObservers for SupportedExecutors<FSV, I, OT, S>
where
    FSV: HasObservers<Observers = OT>,
{
    type Observers = OT;
    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.observers(),
        }
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.observers_mut(),
        }
    }
}

#[cfg(not(feature = "nyx"))]
impl<FSV, I, OT, S> HasTimeout for SupportedExecutors<FSV, I, OT, S>
where
    FSV: HasTimeout,
{
    fn set_timeout(&mut self, timeout: std::time::Duration) {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.set_timeout(timeout),
        }
    }
    fn timeout(&self) -> std::time::Duration {
        match self {
            Self::Forkserver(fsrv, _) => fsrv.timeout(),
        }
    }
}

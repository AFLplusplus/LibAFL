use std::{
    fs::File,
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
};

use libafl::Error;
use memmap2::{Mmap, MmapOptions};

use crate::{Opt, DEFER_SIG, PERSIST_SIG};

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
        #[cfg(target_os = "linux")]
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
    let is_reg = !bin_path.is_symlink() && !bin_path.is_dir();
    let bin_size = metadata.st_size();
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
    if mmap[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        return Err(Error::illegal_argument(format!(
            "Program '{}' is not an ELF binary",
            bin_path.display()
        )));
    }

    #[cfg(all(target_os = "macos", not(target_arch = "arm")))]
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

    #[cfg(target_os = "linux")]
    let check_instrumentation = check_instrumentation && !opt.nyx_mode;

    if check_instrumentation && !is_instrumented(&mmap, shmem_env_var) {
        return Err(Error::illegal_argument(
            "target binary is not instrumented correctly",
        ));
    }

    if opt.forkserver_cs || opt.qemu_mode || opt.frida_mode && is_instrumented(&mmap, shmem_env_var)
    {
        return Err(Error::illegal_argument("Instrumentation found in -Q mode"));
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

fn find_executable_in_path(executable: &Path) -> Option<PathBuf> {
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

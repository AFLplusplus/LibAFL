mod args;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
use {
    crate::args::Args,
    anyhow::{anyhow, Result},
    clap::Parser,
    nix::unistd::execvp,
    std::ffi::CString,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use {
    crate::args::Args,
    anyhow::{anyhow, Result},
    clap::Parser,
    nix::{
        sys::{personality, personality::Persona},
        unistd::execvp,
    },
    std::ffi::CString,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
fn disable_aslr() -> Result<()> {
    let mut persona = personality::get().map_err(|e| anyhow!("Failed to get personality: {e:}"))?;
    persona |= Persona::ADDR_NO_RANDOMIZE;
    personality::set(persona).map_err(|e| anyhow!("Failed to set personality: {e:}"))?;
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn disable_aslr() -> Result<()> {
    let mut status = libc::PROC_ASLR_FORCE_DISABLE;
    let r = unsafe {
        libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_ASLR_CTL,
            &mut core::ptr::from_mut(status) as *mut libc::c_void,
        )
    };
    if r < 0 {
        return Err(anyhow!("Failed to set aslr control"));
    }
    Ok(())
}

#[cfg(target_os = "dragonfly")]
fn disable_aslr() -> Result<()> {
    unsafe {
        let disable: i32 = 0;
        let s = std::mem::size_of::<i32>();
        let nm = CString::new("vm.randomize_mmap")
            .map_err(|e| anyhow!("Failed to create sysctl oid: {e:}"))
            .unwrap();
        if libc::sysctlbyname(
            nm.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &disable as *const i32 as _,
            s,
        ) < 0
        {
            return Err(anyhow!("Failed to disable aslr"));
        }
    }
    Ok(())
}

#[cfg(target_os = "netbsd")]
fn disable_aslr() -> Result<()> {
    unsafe {
        let mut aslr: i32 = 0;
        let mut s = std::mem::size_of::<i32>();
        let nm = CString::new("security.pax.aslr.enabled")
            .map_err(|e| anyhow!("Failed to create sysctl oid: {e:}"))
            .unwrap();
        if libc::sysctlbyname(
            nm.as_ptr(),
            &mut aslr as *mut i32 as _,
            &mut s,
            std::ptr::null(),
            0,
        ) < 0
        {
            return Err(anyhow!("Failed to get aslr status"));
        }

        if aslr > 0 {
            return Err(anyhow!(
                "Please disable aslr with sysctl -w security.pax.aslr.enabled=0 as privileged user"
            ));
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    disable_aslr()?;

    let cargs = args
        .argv()
        .iter()
        .map(|x| CString::new(x.clone()).map_err(|e| anyhow!("Failed to read argument: {e:}")))
        .collect::<Result<Vec<CString>>>()?;

    execvp(&cargs[0], &cargs).map_err(|e| anyhow!("Failed to exceve: {e:}"))?;
    Ok(())
}

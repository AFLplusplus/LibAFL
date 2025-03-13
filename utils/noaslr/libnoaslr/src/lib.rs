#[cfg(any(target_os = "linux", target_os = "android"))]
use {
    anyhow::{anyhow, Result},
    ctor::ctor,
    nix::{
        sys::{personality, personality::Persona},
        unistd::execvpe,
    },
    std::{ffi::CString, fs::File, io::Read},
};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
use {
    anyhow::{anyhow, Result},
    ctor::ctor,
    std::ffi::CString,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_null_lines(path: &str) -> Result<Vec<CString>> {
    let mut file = File::open(path).map_err(|e| anyhow!("Failed to open maps: {e:}"))?;
    let mut data = String::new();
    file.read_to_string(&mut data)
        .map_err(|e| anyhow!("Failed to read command line: {e:}"))?;
    data.split('\0')
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .map(|x| CString::new(x).map_err(|e| anyhow!("Failed to read argument: {e:}")))
        .collect::<Result<Vec<CString>>>()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn libnoaslr() -> Result<()> {
    let mut persona = personality::get().map_err(|e| anyhow!("Failed to get personality: {e:}"))?;
    if (persona & Persona::ADDR_NO_RANDOMIZE) == Persona::ADDR_NO_RANDOMIZE {
        return Ok(());
    }

    persona |= Persona::ADDR_NO_RANDOMIZE;
    personality::set(persona).map_err(|e| anyhow!("Failed to set personality: {e:}"))?;

    let args = read_null_lines("/proc/self/cmdline")?;
    let env = read_null_lines("/proc/self/environ")?;

    execvpe(&args[0], &args, &env).map_err(|e| anyhow!("Failed to exceve: {e:}"))?;
    Ok(())
}

#[cfg(target_os = "freebsd")]
fn libnoaslr() -> Result<()> {
    unsafe extern "C" {
        fn exect(
            c: *const libc::c_char,
            args: *const *const libc::c_char,
            env: *const *const libc::c_char,
        ) -> libc::c_int;
    }
    let mut status = libc::PROC_ASLR_FORCE_DISABLE;
    let mut pargs: Vec<i8> = vec![0; 256];
    let mut penv: Vec<i8> = vec![0; 256];
    let mut s = pargs.len();
    let mib = &mut [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ARGS, -1];
    let miblen = mib.len() as u32;
    unsafe {
        if libc::procctl(
            libc::P_PID,
            0,
            libc::PROC_ASLR_CTL,
            &mut core::ptr::from_mut(status) as *mut libc::c_void,
        ) < 0
        {
            return Err(anyhow!("Failed to set aslr control"));
        }
        if libc::sysctl(
            mib.as_mut_ptr(),
            miblen,
            pargs.as_mut_ptr() as _,
            &mut s,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow!("Failed to get argv"));
        }
        pargs.set_len(s - 1);
        let args = pargs.as_mut_ptr();
        let mut env = std::ptr::null_mut();
        mib[2] = libc::KERN_PROC_ENV;
        s = penv.len();
        if libc::sysctl(
            mib.as_mut_ptr(),
            miblen,
            penv.as_mut_ptr() as _,
            &mut s,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            penv.set_len(s - 1);
            env = penv.as_mut_ptr() as _;
        }
        exect(args.add(0) as _, args as _, env);
    }
    Ok(())
}

#[cfg(target_os = "netbsd")]
fn libnoaslr() -> Result<()> {
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
        let mib = &mut [
            libc::CTL_KERN,
            libc::KERN_PROC_ARGS,
            libc::getpid(),
            libc::KERN_PROC_ARGV,
        ];
        let miblen = mib.len() as u32;
        s = 0;
        if libc::sysctl(
            mib.as_mut_ptr(),
            miblen,
            std::ptr::null_mut(),
            &mut s,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow!("Failed to get argv buffer"));
        }
        let mut pargs: Vec<i8> = Vec::with_capacity(s);
        if libc::sysctl(
            mib.as_mut_ptr(),
            miblen,
            pargs.as_mut_ptr() as _,
            &mut s,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow!("Failed to get argv"));
        }
        mib[3] = libc::KERN_PROC_ENV;
        s = 0;
        if libc::sysctl(
            mib.as_mut_ptr(),
            miblen,
            std::ptr::null_mut(),
            &mut s,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow!("Failed to get env buffer"));
        }
        let mut penv: Vec<i8> = Vec::with_capacity(s);
        if libc::sysctl(
            mib.as_mut_ptr(),
            miblen,
            penv.as_mut_ptr() as _,
            &mut s,
            std::ptr::null_mut(),
            0,
        ) < 0
        {
            return Err(anyhow!("Failed to get argv"));
        }
        let args = pargs.as_mut_ptr();
        let env = penv.as_mut_ptr() as _;
        libc::execvpe(args.add(0) as _, args as _, env);
    }
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
#[ctor]
fn init() {
    libnoaslr().unwrap();
}

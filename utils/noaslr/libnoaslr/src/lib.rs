use {
    anyhow::{anyhow, Result},
    ctor::ctor,
    nix::{
        sys::{personality, personality::Persona},
        unistd::execvpe,
    },
    std::{ffi::CString, fs::File, io::Read},
};

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

#[ctor]
fn init() {
    libnoaslr().unwrap();
}

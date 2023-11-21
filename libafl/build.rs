use std::error::Error;

#[rustversion::nightly]
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=nightly");
    #[cfg(feature = "unicode")]
    {
        build_unicode_property_map()?;
    }
    Ok(())
}

#[rustversion::not(nightly)]
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    assert!(
        cfg!(all(not(docrs), not(feature = "nautilus"))),
        "The 'nautilus' feature of libafl requires a nightly compiler"
    );
    #[cfg(feature = "unicode")]
    {
        build_unicode_property_map()?;
    }
    Ok(())
}

#[cfg(feature = "unicode")]
fn build_unicode_property_map() -> Result<(), Box<dyn Error>> {
    use std::{
        env,
        fs::File,
        io::{BufWriter, Write},
        path::PathBuf,
        process::{Command, Stdio},
    };

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let ucd_dir = out_dir.join("ucd-dir");
    let generated_file = out_dir.join("unicode_categories.rs");

    std::fs::create_dir_all(&ucd_dir)?;

    let zip_path = ucd_dir.join("ucd.zip");
    let mut ucd_file = BufWriter::new(File::create(&zip_path)?);
    for chunk in reqwest::blocking::get("https://www.unicode.org/Public/zipped/latest/UCD.zip")?
        .bytes()?
        .chunks(1 << 12)
    {
        ucd_file.write_all(chunk)?;
    }
    ucd_file.flush()?;
    drop(ucd_file);

    let mut zip_file = zip::ZipArchive::new(File::open(&zip_path)?)?;
    zip_file.extract(&ucd_dir)?;
    drop(zip_file);

    std::fs::remove_file(zip_path)?;

    let status = Command::new("ucd-generate")
        .arg("general-category")
        .arg(ucd_dir.as_os_str())
        .stdout(Stdio::from(File::create(generated_file)?))
        .status()?;
    assert!(status.success());

    Ok(())
}

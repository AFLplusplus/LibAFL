#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location $SCRIPT_DIR

if ($args.Count -eq 0) {
    $profile = "release"
} else {
    $profile = $args[0]
}

try {
    $nightly_version = Invoke-Expression "cargo +nightly --version" 2>$null
    if (-not $nightly_version) {
        Write-Host "You must install a recent Rust nightly to build the libafl_libfuzzer runtime!" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "You must install a recent Rust nightly to build the libafl_libfuzzer runtime!" -ForegroundColor Red
    exit 1
}

Write-Host "Building libafl_libfuzzer runtime with profile '$profile'" -ForegroundColor Green
Invoke-Expression "cargo +nightly build --profile $profile"

# target-libdir is e.g. C:\Users\user\.rustup\toolchain\nightly-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\lib
$RUSTC_BIN = Split-Path -Parent (Invoke-Expression "cargo +nightly rustc -Zunstable-options --print target-libdir")
$RUSTC_BIN = Join-Path $RUSTC_BIN "bin"
$RUST_LLD = Join-Path $RUSTC_BIN "rust-lld.exe"
$RUST_AR = Join-Path $RUSTC_BIN "llvm-ar.exe"
$RUST_NM = Join-Path $RUSTC_BIN "llvm-nm.exe"

if (-not (Test-Path $RUST_LLD) -or -not (Test-Path $RUST_AR)) {
    Write-Host "You must install the llvm-tools component: 'rustup component add llvm-tools'" -ForegroundColor Red
    Write-Host "Could not find $RUST_LLD or $RUST_AR" -ForegroundColor Red
    exit 1
}

$tmpdir = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpdir | Out-Null

function Cleanup {
    if (Test-Path $tmpdir) {
        Remove-Item -Recurse -Force $tmpdir
    }
}

try {
    $targetPath = Join-Path $SCRIPT_DIR "target\$profile\afl_libfuzzer_runtime.lib"
    $outputPath = Join-Path $SCRIPT_DIR "libFuzzer.lib"
    
    Write-Host "Creating intermediate object file '$tmpdir\libFuzzer.obj from $targetPath'" -ForegroundColor Green
    & $RUST_LLD -flavor link /lib /nologo /out:"$tmpdir\libFuzzer.obj" "$targetPath"
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create intermediate object file"
    }
    
    Write-Host "Creating final library '$outputPath'" -ForegroundColor Green
    & $RUST_AR crs "$outputPath" "$tmpdir\libFuzzer.obj"
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create final library"
    }

    Write-Host "Verifying symbols from '$outputPath'" -ForegroundColor Green
    # Symbols that should be present:
    # LLVMFuzzerRunDriver
    & $RUST_NM "$outputPath" | Select-String "LLVMFuzzerRunDriver" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to verify symbols in final library"
    }

    Write-Host "Done! Wrote the runtime to '$outputPath'" -ForegroundColor Green

}
finally {
    Cleanup
}
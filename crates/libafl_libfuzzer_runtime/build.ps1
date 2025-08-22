#!/usr/bin/env pwsh
param (
    [Parameter(Mandatory = $false, HelpMessage = "The build profile to use, e.g. 'release' or 'dev'. Default is 'release'.")]
    [string]$Profile = "release",
    [Parameter(Mandatory = $false, HelpMessage = "The toolchain to use, e.g. 'stable', 'nightly', etc. Default is 'stable'.")]
    [string]$Toolchain = "stable",
    [Parameter(Mandatory = $false, HelpMessage = "Additional cargo arguments to pass")]
    [string]$CargoArgs = "",
    [Parameter(Mandatory = $false, HelpMessage = "Additional rustc arguments to pass")]
    [string]$RustcArgs = "",
    [Parameter(Mandatory = $false, HelpMessage = "Additional flags to set for the C compiler")]
    [string]$CCFlags = ""
)

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location $SCRIPT_DIR

Write-Host "Building libafl_libfuzzer runtime with profile '$Profile' on toolchain '$Toolchain'" -ForegroundColor Green
Invoke-Command -ScriptBlock {
    $env:RUSTFLAGS = $RustcArgs
    $env:CFLAGS = $CCFlags
    Write-Host "Using Rust flags: $env:RUSTFLAGS" -ForegroundColor Cyan
    Write-Host "Using Cargo arguments: $CargoArgs" -ForegroundColor Cyan
    Write-Host "Using C compiler flags: $env:CFLAGS" -ForegroundColor Cyan
    if ($CargoArgs) {
        cargo +$Toolchain build --profile $Profile $CargoArgs
    } else {
        cargo +$Toolchain build --profile $Profile
    }
}


$tmpdir = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpdir | Out-Null

function Cleanup {
    if (Test-Path $tmpdir) {
        Remove-Item -Recurse -Force $tmpdir
    }
}

try {
    if ($Profile -eq "dev") {
        # Set the profile to debug for dev builds, because the path isn't the same
        # as the profile name
        $Profile = "debug"
    }

    $targetPath = Join-Path $SCRIPT_DIR "target\$Profile\afl_libfuzzer_runtime.lib"
    $outputPath = Join-Path $SCRIPT_DIR "libFuzzer.lib"
    
    Copy-Item -Path $targetPath -Destination $outputPath -Force | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to copy final library"
    }

    Write-Host "Done! Wrote the runtime to '$outputPath'" -ForegroundColor Green
} finally {
    Cleanup
}
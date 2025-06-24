#!/usr/bin/env pwsh

$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location $SCRIPT_DIR

if ($args.Count -eq 0) {
    $profile = "release"
} else {
    $profile = $args[0]
}

Write-Host "Building libafl_libfuzzer runtime with profile '$profile'" -ForegroundColor Green
Invoke-Expression "cargo build --profile $profile"

$tmpdir = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmpdir | Out-Null

function Cleanup {
    if (Test-Path $tmpdir) {
        Remove-Item -Recurse -Force $tmpdir
    }
}

try {
    if ($profile -eq "dev") {
        # Set the profile to debug for dev builds, because the path isn't the same
        # as the profile name
        $profile = "debug"
    }

    $targetPath = Join-Path $SCRIPT_DIR "target\$profile\afl_libfuzzer_runtime.lib"
    $outputPath = Join-Path $SCRIPT_DIR "libFuzzer.lib"
    
    Copy-Item -Path $targetPath -Destination $outputPath -Force | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to copy final library"
    }

    Write-Host "Done! Wrote the runtime to '$outputPath'" -ForegroundColor Green
} finally {
    Cleanup
}
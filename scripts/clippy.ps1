# Clippy Runner Script for PowerShell (Windows)

$ErrorActionPreference = "Stop"  # This is similar to set -e in Bash
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent $ScriptDir)

# Function to run Clippy on a single directory
function Run-Clippy {
    param (
        [string]$dir
    )
    Write-Host "Running Clippy on $dir"
    Push-Location $dir

    $currentdir = $PWD.Path
    Write-Host "Running Clippy in $currentdir"
    
    try {
        $env:RUST_BACKTRACE = "full"
        cargo +nightly clippy --all-features --no-deps --tests --examples --benches -- -Z macro-backtrace `
            -D clippy::all `
            -D clippy::pedantic `
            -W clippy::similar_names `
            -A clippy::type_repetition_in_bounds `
            -A clippy::missing-errors-doc `
            -A clippy::cast-possible-truncation `
            -A clippy::used-underscore-binding `
            -A clippy::ptr-as-ptr `
            -A clippy::missing-panics-doc `
            -A clippy::missing-docs-in-private-items `
            -A clippy::unseparated-literal-suffix `
            -A clippy::module-name-repetitions `
            -A clippy::unreadable-literal

        # Exit unsuccessfully on clippy error
        if (!$?) {
            exit 1
        }
    }
    finally {
        Pop-Location
    }
}

# Define projects for Windows
$AllProjects = @(
    "libafl_concolic/test/dump_constraints",
    "libafl_concolic/test/runtime_test",
    "libafl_libfuzzer",
    "libafl_nyx",
    "libafl_sugar",
    "libafl_tinyinst"
    "utils/build_and_test_fuzzers",
    "utils/deexit",
    "utils/libafl_benches",
    "utils/gramatron/construct_automata"
)

# Check if arguments were provided
if ($args.Count -eq 0) {
    # No arguments provided, run on all projects
    $Projects = $AllProjects
}
else {
    # Arguments provided, split the input string into an array
    $Projects = $args[0] -split ','
}

# First run it on all default members
$env:RUST_BACKTRACE = "full"
cargo +nightly clippy --all-features --no-deps --tests --examples --benches -- -Z macro-backtrace `
    -D clippy::all `
    -D clippy::pedantic `
    -W clippy::similar_names `
    -A clippy::type_repetition_in_bounds `
    -A clippy::missing-errors-doc `
    -A clippy::cast-possible-truncation `
    -A clippy::used-underscore-binding `
    -A clippy::ptr-as-ptr `
    -A clippy::missing-panics-doc `
    -A clippy::missing-docs-in-private-items `
    -A clippy::unseparated-literal-suffix `
    -A clippy::module-name-repetitions `
    -A clippy::unreadable-literal

# Exit unsuccessfully on clippy error
if (!$?) {
    exit 1
}

# Loop through each project and run Clippy
foreach ($project in $Projects) {
    $project = $project.Trim()
    if (Test-Path $project -PathType Container) {
        Run-Clippy $project
    }
    else {
        Write-Host "Warning: Directory $project does not exist. Skipping."
    }
}

Write-Host "Clippy run completed for all specified projects."
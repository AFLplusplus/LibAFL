# LibFuzzer Example for Windows with ASAN

This folder contains an example fuzzer for Windows which also uses ASAN.

We are initializing LibAFL to be compatible with ASAN.

## Setup

We are currently using Clang on Windows. Make sure to install Clang through the Visual Studio installer.

We recommend using Powershell and enabling the Visual Studio environment using this script:

```powershell
Push-Location "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\"
& "C:\\Windows\System32\cmd.exe" /c "vcvars64.bat & set" |
ForEach-Object {
  if ($_ -match "=") {
    $v = $_.split("=", 2); set-item -force -path "ENV:\$($v[0])"  -value "$($v[1])" 
  }
}
Pop-Location
Write-Host "`nVisual Studio 2022 Command Prompt variables set." -ForegroundColor Yellow
````

After that clang should be available in the PATH.

## Build

To build the fuzzer and link against the `harness.cpp` in this example run: 

```
cargo make fuzzer
```

## Running

```
.\libfuzzer_windows_asan.exe
```

## Note on MSVC

The MSVC compiler (`cl.exe`) will work in the future. Currently, it is blocked because of a [bug](https://developercommunity.visualstudio.com/t/__sanitizer_cov_trace_pc_guard_init-neve/10218995) with coverage.

### Note on ASAN

Using ASAN on Windows with MSVC is not trivial as of 2022. Depending on the harness and fuzzing target, the required compilation flags differ. Most notably, the usage of `/MT` and `/MD` for the CRT is important. All compilation artifacts should use the same config for the CRT (either all `/MT` or all `/MD`). [Rust uses as of 2022](https://rust-lang.github.io/rfcs/1721-crt-static.html) `/MD` as default. So compile everything with `/MD`.

Depending on the linking mode different ASAN libraries get linked. Definitely read [this](https://devblogs.microsoft.com/cppblog/addresssanitizer-asan-for-windows-with-msvc/) blog post by Microsoft.

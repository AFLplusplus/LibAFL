# LibAFL Frida_Windows_GdiPlus Example

This is a an example how to fuzz binary-only dlls on Windows.
The example fuzzer will explore [gdiplus](https://learn.microsoft.com/en-us/windows/win32/gdiplus/-gdiplus-gdi-start) on Windows, using the [Frida](https://frida.re/) DBI.

## Build

To build this example, run `cargo build --release` in this folder.

Then compile the harness `cl.exe /LD harness.cc /link /dll gdiplus.lib ole32.lib`

## Run

To run the example `target\release\frida_windows_gdiplus.exe -H harness.dll -i corpus -o output --libs-to-instrument gdi32.dll --libs-to-instrument gdi32full.dll --libs-to-instrument gdiplus.dll --libs-to-instrument WindowsCodecs.dll --disable-excludes`

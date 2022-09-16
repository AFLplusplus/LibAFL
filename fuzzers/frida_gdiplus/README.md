## Build

To build this example, run `cargo build --release` in this folder.

Then compile the harness `cl.exe /LD harness.cc /link /dll gdiplus.lib ole32.lib`

## Run

`target\release\frida_gdiplus.exe -H harness.dll -i corpus -o output`

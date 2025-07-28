# libvharness

Libvharness is a cross-architecture and cross-platform library to create LibAFL QEMU compatible harnesses.
It can be built for a large variety of target architectures, for different OSes, while sharing the same API.
Two APIs are supported: LibAFL QEMU (lqemu) and Nyx.

## Build

The usual stuff for cmake project:

```bash
mkdir build
cd build
cmake ..
make -j
cmake --install . --prefix <install_path>
```

## Configuration

There are a few Cmake variables to modify to adapt the build to your needs.

- `CMAKE_TOOLCHAIN_FILE`: points to one of the files in `toolchains`, to choose depending on the target arch.
- `VHARNESS_API`: either `lqemu` or `nyx`, to choose the target API.

You may also have to configure the right compiler toolchain, using the usual cmake variables for that.

## Usage

Once the build is done, `<install_path>` will contain 2 directories: `include` and `lib`.

- `lib`: contains the static library to link with. Should be linked with your harness.
- `include`: the include files to use. there are 2 files that should be interesting to include:
    - `lqemu.h` if using the LibAFL QEMU API.
    - `nyx.h` if using the Nyx API.
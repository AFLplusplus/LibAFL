# LibAFL CC

LibAFL CC provides the functionalities to write compiler wrappers for LibAFL, by providing to the user a set of compiler extensions useful for instrumentation.

The online documentation for this crate is available [here](https://docs.rs/crate/libafl_cc/latest).

Currently, we support LLVM version 11 up to 17, but other versions may work.
To install LLVM, use the official [download page](https://releases.llvm.org/download.html).

The LLVM tools (including clang, clang++) are needed (newer than LLVM 11.0.0 up to LLVM 17.0.0)
 - When compiling LLVM tools on Windows, you can try to compile LLVM with the below commands (tested on LLVM 16.0.6).
 - NOTE: This assumes you have Visual Studio 17 2022 and MSVC v143 Tools installed under "Individual Components"
```sh
## Start x64 Native Tools Command Prompt for VS 2022
RUN AS ADMINISTRATOR: %comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

## Cloning the LLVM project repo
git clone https://github.com/llvm/llvm-project.git llvm

## Building Clang project first, the CMAKE_INSTALL_PREFIX is important here, make sure to select a folder path that doesn't contain any spaces in it
$ cmake -S llvm\llvm -B build -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=X86 -Thost=x64 -DCMAKE_INSTALL_PREFIX=C:\llvm
$ cd build
$ cmake --build . --target install --config release

## Building lld project first, the CMAKE_INSTALL_PREFIX is important here, make sure to select a folder path that doesn't contain any spaces in it
## Changing back to the previous directory
$ cd .. 
$ cmake -S llvm\llvm -B build -DLLVM_ENABLE_PROJECTS=lld -DLLVM_TARGETS_TO_BUILD=X86 -Thost=x64 -DCMAKE_INSTALL_PREFIX=C:\llvm
$ cd build
$ cmake --build . --target install --config release
```

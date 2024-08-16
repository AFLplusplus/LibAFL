# Setup

The first step is to download LibAFL and all dependencies that are not automatically installed with `cargo`.

> ### Command Line Notation
>
> In this chapter and throughout the book, we show some commands used in the
> terminal. Lines that you should enter in a terminal all start with `$`. You
> don’t need to type in the `$` character; it indicates the start of each
> command. Lines that don’t start with `$` typically show the output of the
> previous command. Additionally, PowerShell-specific examples will use `>`
> rather than `$`.

While technically you do not need to install LibAFL, but can use the version from crates.io directly, we do recommend to download or clone the GitHub version.
This gets you the example fuzzers, additional utilities, and latest patches.
The easiest way to do this is to use `git`.

```sh
$ git clone https://github.com/AFLplusplus/LibAFL.git
```

Alternatively, on a UNIX-like machine, you can download a compressed archive and extract it with:

```sh
$ wget https://github.com/AFLplusplus/LibAFL/archive/main.tar.gz
$ tar xvf main.tar.gz
$ rm main.tar.gz
$ ls LibAFL-main # this is the extracted folder
```

## Clang installation

One of the external dependencies of LibAFL is the Clang C/C++ compiler.
While most of the code is written in pure Rust, we still need a C compiler because stable Rust still does not support features that some parts of LibAFL may need, such as weak linking, and LLVM builtins linking.
For these parts, we use C to expose the missing functionalities to our Rust codebase.

In addition, if you want to perform source-level fuzz testing of C/C++ applications,
you will likely need Clang with its instrumentation options to compile the programs
under test.

On Linux you could use your distribution's package manager to get Clang,
but these packages are not always up-to-date.
Instead, we suggest using the Debian/Ubuntu prebuilt packages from LLVM that are available using their [official repository](https://apt.llvm.org/).

For Microsoft Windows, you can download the [installer package](https://llvm.org/builds/) that LLVM generates periodically.

Despite Clang being the default C compiler on MacOS, we discourage the use of the build shipped by Apple and encourage
the installation from [Homebrew](https://brew.sh/), using `brew install llvm`.

Alternatively, you can download and build the LLVM source tree - Clang included - following the steps
explained [here](https://clang.llvm.org/get_started.html).

## Rust installation

If you do not have Rust installed, you can easily follow the steps described [here](https://www.rust-lang.org/tools/install)
to install it on any supported system.
Be aware that Rust versions shipped with Linux distributions may be outdated, LibAFL always targets the latest `stable` version available via `rustup update`.

We suggest installing Clang and LLVM first.

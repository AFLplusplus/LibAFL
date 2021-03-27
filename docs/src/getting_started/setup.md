# Setup

The first step is to download LibAFL and all its dependencies that are not automatically installed with `cargo`.

> ### Command Line Notation
>
> In this chapter and throughout the book, we’ll show some commands used in the
> terminal. Lines that you should enter in a terminal all start with `$`. You
> don’t need to type in the `$` character; it indicates the start of each
> command. Lines that don’t start with `$` typically show the output of the
> previous command. Additionally, PowerShell-specific examples will use `>`
> rather than `$`.

The easiest way to download LibAFL is using `git`.

```sh
$ git clone git@github.com:AFLplusplus/LibAFL.git
```

You can alternatively, on a UNIX-like machine, download a compressed archive and extract with:

```sh
$ wget https://github.com/AFLplusplus/LibAFL/archive/main.tar.gz
$ tar xvf LibAFL-main.tar.gz
$ rm LibAFL-main.tar.gz
$ ls LibAFL-main # this is the extracted folder
```

## Clang installation

One of the external dependencies of LibAFL is the Clang C/C++ compiler.
While most of the code is in pure Rust, we still need a C compiler because Rust stable
still does not support features that we need such as weak linking and LLVM builtins linking,
and so we use C to expose the missing functionalities to our Rust codebase.

In addition, if you want to perform source-level fuzz testing of C/C++ applications,
you will likely need Clang with its instrumentation options to compile the programs
under test.

You can download and build the LLVM source tree, Clang included, following the steps
explained [here](https://clang.llvm.org/get_started.html).

Alternatively, on Linux, you can use your distro's package manager to get Clang,
but these packages are not always updated, so we suggest you to use the
Debian/Ubuntu prebuilt packages from LLVM that are available using their [official repository](https://apt.llvm.org/).

For Miscrosoft Windows, you can download the [installer package](https://llvm.org/builds/) that LLVM generates periodically.

Despite that Clang is the default C compiler on macOS, we discourage the use of the build shipped by Apple and encourage
the installation from `brew` or direclty a fresh build from the source code.

## Rust installation

If you don't have Rust installed, you can easily follow the steps described [here](https://www.rust-lang.org/tools/install)
to install it on any supported system.

We suggest to install Clang and LLVM first.


# NOASLR
`noaslr` is a launcher for running applications with ASLR disabled without having
to disable the feature system-wide.

`libnoaslr` is a dynamic shared object which can be injected into an application
at startup using `LD_PRELOAD` which will cause it to disable ASLR.

Also included is `demo` an application which reads and prints the contents of the
file passed as its single argument. By passing `/proc/self/maps` as its argument
it can be observed that the application loads at the same default address each
time it is run.

# Test
## App
```
$ just run
```
## Library

```
$ just runlib
```

# Example
## App
```
$ ./target/debug/noaslr ./target/debug/demo -- /proc/self/maps
```
## Library

```
$ LD_PRELOAD=target/debug/libnoaslr.so ./target/debug/demo /proc/self/maps
```

## Output
...

555555554000-55555556d000 r--p 00000000 fd:03 78381550                   /home/jon/git/LibAFL/utils/noaslr/target/debug/demo
55555556d000-5555556a1000 r-xp 00019000 fd:03 78381550                   /home/jon/git/LibAFL/utils/noaslr/target/debug/demo
5555556a1000-5555556ee000 r--p 0014d000 fd:03 78381550                   /home/jon/git/LibAFL/utils/noaslr/target/debug/demo
5555556ee000-5555556fb000 r--p 00199000 fd:03 78381550                   /home/jon/git/LibAFL/utils/noaslr/target/debug/demo
5555556fb000-5555556fc000 rw-p 001a6000 fd:03 78381550                   /home/jon/git/LibAFL/utils/noaslr/target/debug/demo
5555556fc000-55555571d000 rw-p 00000000 00:00 0                          [heap]
7ffff7d74000-7ffff7d76000 rw-p 00000000 00:00 0
7ffff7d76000-7ffff7d98000 r--p 00000000 fd:03 9972607                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7d98000-7ffff7f10000 r-xp 00022000 fd:03 9972607                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f10000-7ffff7f5e000 r--p 0019a000 fd:03 9972607                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f5e000-7ffff7f62000 r--p 001e7000 fd:03 9972607                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f62000-7ffff7f64000 rw-p 001eb000 fd:03 9972607                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f64000-7ffff7f68000 rw-p 00000000 00:00 0
7ffff7f68000-7ffff7f69000 r--p 00000000 fd:03 9972611                    /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7ffff7f69000-7ffff7f6b000 r-xp 00001000 fd:03 9972611                    /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7ffff7f6b000-7ffff7f6c000 r--p 00003000 fd:03 9972611                    /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7ffff7f6c000-7ffff7f6d000 r--p 00003000 fd:03 9972611                    /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7ffff7f6d000-7ffff7f6e000 rw-p 00004000 fd:03 9972611                    /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7ffff7f6e000-7ffff7f74000 r--p 00000000 fd:03 9972655                    /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7ffff7f74000-7ffff7f85000 r-xp 00006000 fd:03 9972655                    /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7ffff7f85000-7ffff7f8b000 r--p 00017000 fd:03 9972655                    /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7ffff7f8b000-7ffff7f8c000 r--p 0001c000 fd:03 9972655                    /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7ffff7f8c000-7ffff7f8d000 rw-p 0001d000 fd:03 9972655                    /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7ffff7f8d000-7ffff7f91000 rw-p 00000000 00:00 0
7ffff7f91000-7ffff7f94000 r--p 00000000 fd:03 9961835                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7f94000-7ffff7fa6000 r-xp 00003000 fd:03 9961835                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7fa6000-7ffff7faa000 r--p 00015000 fd:03 9961835                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7faa000-7ffff7fab000 r--p 00018000 fd:03 9961835                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7fab000-7ffff7fac000 rw-p 00019000 fd:03 9961835                    /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffff7fac000-7ffff7fae000 rw-p 00000000 00:00 0
7ffff7fc8000-7ffff7fc9000 ---p 00000000 00:00 0
7ffff7fc9000-7ffff7fcb000 rw-p 00000000 00:00 0
7ffff7fcb000-7ffff7fce000 r--p 00000000 00:00 0                          [vvar]
7ffff7fce000-7ffff7fcf000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fcf000-7ffff7fd0000 r--p 00000000 fd:03 9972533                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7fd0000-7ffff7ff3000 r-xp 00001000 fd:03 9972533                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ff3000-7ffff7ffb000 r--p 00024000 fd:03 9972533                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffc000-7ffff7ffd000 r--p 0002c000 fd:03 9972533                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffd000-7ffff7ffe000 rw-p 0002d000 fd:03 9972533                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]

```

# About
## APP
`noaslr` does the following:
* Uses the `personality` API to set the flag `ADDR_NO_RANDOMIZE`.
* Uses the `execve` API to launch the child application.

## Lib
`libnoasl` does the following:
* Uses rusts `ctor` crate to define a function as `__attribute__((constructor))`
* Uses the `personality` API to determine if the flag `ADDR_NO_RANDOMIZE` is set
* If the flag is set, the constructor returns, otherwise...
* Uses the `personality` API again to set the flag
* Reads the program arguments from `/proc/self/cmdline`
* Reads the program environment variables from `/proc/self/environ`
* Uses the `execvpe` API to re-launch the application

# Usage
```
Tool launching applications with ASLR disabled

Usage: noaslr <PROGRAM> [-- <ARGS>...]

Arguments:
  <PROGRAM>
          Name of the application to launch

  [ARGS]...
          Arguments passed to the target

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

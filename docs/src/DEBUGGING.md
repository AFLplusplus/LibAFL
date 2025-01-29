# General debugging tips
This file answers some commmon questions that arise when you are writing a fuzzer using LibAFL.

## Q. My fuzzer crashed but the stack trace is useless.
You can enable the `errors_backtrace` feature of the `libafl` crate. With this the stacktrace is meaningful.

## Q. I started the fuzzer but the corpus count is 0.
Unless the initial corpus is loaded with the "load_initial_inputs_forced" function, we only store the interesting inputs, which is the inputs that triggered the feedback. So this usually means that your input was not interesting or your target was simply not properly implemented. 
Either way, what you can do is attach to the executable with gdb and set a breakpoint at where the new edges should be reported. If no instrumentation code is executed, then the the problem is in the instrumentation. If the instrumentation code is hit, but still the your input is not instrumented, then the problem could be that you are not passign the observer/feedback correctly to the fuzzer.

## Q. I started the fuzzer but the coverage is 0.
This could mean two things. Perhaps your target was not properly instrumented, or you are not using the correct observer, feedback feature.
In this case, again, what usually should do is to run the fuzzer with gdb and set a breakpoint at where the coverage is recorded (e.g. __sanitizer_coverage_trace_pcguard), and validate that the target is giving the feedback to the fuzzer.

## Q. I started the fuzzer but there's no output.
First, verify that your stdout and stderr are not redirected to `/dev/null`. If you get the log, then it should either fall into the previous 2 cases. Either the fuzzer crashed because you didn't have the initial seeds, or the coverage feedback is not working.

## Q. My fuzzer is slow.
Try running the fuzzer with the `introspection` feature of the `libafl`. This will show how much time is spent on each module of your fuzzer. Also you might be using a wrong size of the coverage map. If you see `2621440` for the size of the coverage map, you are doing it wrong. One possible mistake is the misuse of `libafl_targets::coverage::EDGES_MAP`
```
let map = StdMapObserver::from_mut_ptr("edges", EDGES_MAP.as_mut_ptr(), EDGES_MAP.len());
```
You should *never* use the `EDGES_MAP`'s size as this is just the size of the allocated size of the coverage map. Consider using something smaller or our default value `libafl_targets::LIBAFL_EDGES_MAP_DEFAULT_SIZE`.

## Q. I still have problems with my fuzzer.
Finally, if you really have no idea what is going on, run your fuzzer with logging enabled. (You can use `env_logger`, `SimpleStdoutLogger`, `SimpleStderrLogger` from `libafl_bolts`. `fuzzbench_text` has an example to show how to use it.) (Don't forget to enable stdout and stderr), and you can open an issue or ask us in Discord.

## Q. My fuzzer died of `Storing state in crashed fuzzer instance did not work`.
If the exit code is zero, then this is because either your harness exited or you are using fuzzer_loop_for and forgot to add `mgr.on_restart` at the end of the fuzzer. In the first case, you should patch your harness not to exit. (or use `utils/deexit`).

## Q. I can't leave the TUI screen
Type `q` then you leave TUI.

## Q. I see `QEMU internal SIGSEGV {code=MAPERR, addr=0x48}` and my QEMU fuzzer doesn't run.
Are you running QEMU fuzzer on WSL? You have to enable vsyscall https://github.com/microsoft/WSL/issues/4694#issuecomment-556095344.
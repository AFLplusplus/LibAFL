This folder contains all the code necessary to run a smoke test of the whole concolic tracing setup.
This is achieved by
1. Compiling SymCC. Dependencies are installed via `smoke_test_ubuntu_deps.sh`.
2. Compiling a custom runtime with tracing capability (`runtime_test`).
3. Compiling a test program using SymCC that instruments using the custom runtime.
4. Capturing an execution trace of the instrumented target using `dump_constraints` and a fixed input (`if_test_input`).
5. Snapshot-testing the captured trace against our expectation (`expected_constraints.txt`).

This whole process is orchestrated by `smoke_test.sh`.

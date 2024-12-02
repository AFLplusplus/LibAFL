#!/usr/bin/env bash

cargo test intel_pt_trace_fork --no-run

for test_bin in ../target/debug/deps/integration_tests_linux-*; do
  if file "$test_bin" | grep -q "ELF"; then
    sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep "$test_bin"
  fi
done

cargo test intel_pt_trace_fork -- --show-output

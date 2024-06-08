#!/usr/bin/python3
import subprocess
import os
import sys
import math

# Current CI Runner
ci_instances = 18

if len(sys.argv) != 2:
    exit(1)

instance_idx = int(sys.argv[1])

# Set llvm config
os.environ["LLVM_CONFIG"] = "llvm-config"

command = (
    "DOCS_RS=1 cargo hack check --workspace --each-feature --clean-per-run "
    "--exclude-features=prelude,python,sancov_pcguard_edges,arm,aarch64,i386,be,systemmode,whole_archive "
    "--no-dev-deps --exclude libafl_libfuzzer --print-command-list"
)

# Run the command and capture the output
output = subprocess.check_output(command, shell=True, text=True)
output = output.strip().split("\n")[0:]
all_task_cnt = len(output) // 2  # by 2 cuz one task has two lines
task_per_core = math.ceil(all_task_cnt // ci_instances)
print(task_per_core, "tasks assigned to this instance")

for task in output[
    instance_idx * 2 * task_per_core : (instance_idx + 1) * 2 * task_per_core
]:
    print("Running ", task)
    print(os.environ)
    if "libafl_frida" in task:
        # DOCS_RS is needed for libafl_frida to build without auto-download feature
        cargo_check = subprocess.check_output(task, shell=True, text=True, env=dict(os.environ, DOCS_RS="1"))
    else:
        cargo_check = subprocess.check_output(task, shell=True, text=True)
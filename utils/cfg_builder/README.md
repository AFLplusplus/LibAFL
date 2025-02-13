# CFG Builder

This script builds the control flow graph (CFG) of the whole program.

To use this, first you have to setup libafl_cc with `LLVMPasses::DumpCfg` pass.
Then, compile the program with env var `CFG_OUTPUT_PATH`. The llvm pass will dump the cfg of each module into `CFG_OUTPUT_PATH` directory.

After that, you can run `CFG_OUTPUT_PATH=<directory> python3 build.py`, and then you'll get the control flow graph in cfg.xdot and call graph in cg.xdot
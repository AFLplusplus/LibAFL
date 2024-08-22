# More Examples

Examples can be found under `./fuzzers/baby`.

|fuzzer name|usage|
|  ----  | ----  |
| baby_fuzzer_gramatron  | [Gramatron](https://github.com/HexHive/Gramatron) is a fuzzer that uses **grammar automatons** in conjunction with aggressive mutation operators to synthesize complex bug triggers |
| baby_fuzzer_grimoire  |  [Grimoire](https://www.usenix.org/system/files/sec19-blazytko.pdf) is a fully automated coverage-guided fuzzer which works **without any form of human interaction or pre-configuration** |
| baby_fuzzer_nautilus | [nautilus](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-3_Aschermann_paper.pdf) is a **coverage guided, grammar based** fuzzer|
|baby_fuzzer_tokens| basic **token level** fuzzer with token level mutations|
|baby_fuzzer_with_forkexecutor| example for **InProcessForkExecutor**|
|baby_no_std|a minimalistic example how to create a libafl based fuzzer that works on **`no_std`** environments like TEEs, Kernels or on bare metal|

# libafl_wizard

<img align="right" src="./icons/libafl_wizard.png" alt="libafl_wizard logo" width="250" heigh="250">

libafl_wizard is a tool to generate fuzzers using libafl's components. By answering some questions, you can generate your own fuzzer to test programs and help with the development of more secure code, all that while learning more about libafl and how it's used!

## Usage

libafl_wizard has a cli interface and can be run with:

```
cargo run
```

## Have in mind that...

The tool makes use of [graphviz](https://graphviz.org/download/) to generate an image containing the flowchart of the questions diagram, so the users can know beforehand where the answers will take them. Make sure it's installed before running the tool.

When writing answers, the check if an input is a valid answer is such that it simply verifies if what's typed by the user has the same characters so far as the answer (check out `validate_input()`). The thing is that, e.g. if "Crash or Timeout" and "Crash" are both valid answers, if the user answers "crash", the first option will be deemed correct (even though the user wanted the second one). To avoid that, for now, one can simply reverse these answers, so "Crash" comes before "Crash or Timeout".

## Contributing

libafl_wizard uses the `questions.toml` TOML file to store and load the questions that will be asked during the generation process. Each question contains some fields, like the possible answers for that question and the Rust code associated to those answers. As libafl's components get updated or new ones introduced, the questions need to be updated as well.

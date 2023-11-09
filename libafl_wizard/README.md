# libafl_wizard

<img align="right" src="./icons/libafl_wizard.png" alt="libafl_wizard logo" width="250" heigh="250">

libafl_wizard is a tool to generate fuzzers using libafl's components. By answering some questions, you will learn more about how libafl is used and generate your own fuzzer to test programs and help with the development of more secure code!

## Usage

(Probably remove this)
libafl_wizard has a UI, made with [Slint](https://slint.dev/releases/1.1.1/docs/slint/), to help during the process. You can choose between answers by simply clicking on them and visualize where these answers might take you through a flowchart!

```
cargo run --features ui
```

If you don't want or can't use libafl_wizard with the UI, it's possible to use the CLI version, but, as of now, this version doesn't contain a flowchart.

```
cargo run
```

libafl_wizard also generates `flowchart.png`, an image to have an overall view of the questions diagram. Have in mind that this feature requires [Graphviz](https://graphviz.org/download/) to be installed on the machine.

## Contributing
libafl_wizard uses the `questions.toml` TOML file to store and load the questions that will be asked during the generation process. Each question contains some fields, like the possible answers for that question and the Rust code associated to those answers. As libafl's components get updated or new ones introduced, the questions need to be updated as well.

(this as well)
For changes on the UI, please check the [Slint](https://slint.dev/releases/1.1.1/docs/slint/) documentation page to learn more about the language!

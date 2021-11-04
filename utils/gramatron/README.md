# Gramatron preprocessing scripts

In this folder live the scripts to convert a grammar (some examples in the `grammars/` subfolder) into a serialized Automaton.

You need as first to convert the grammar to the GNF form using the `gnf_converter.py` Python script.

Then use the output as input of the `construct_automata` crate.

Here an example using the Ruby grammar:

```
./gnf_converter.py --gf grammars/ruby_grammar.json --out ruby_gnf.json --start PROGRAM
cd construct_automata
RUSTFLAGS="-C target-cpu=native" cargo run --release -- --gf ../ruby_gnf.json --out ../ruby_automaton.postcard
```

You can add the `--limit` flag to limit the stack size, as described in the Gramatron paper.

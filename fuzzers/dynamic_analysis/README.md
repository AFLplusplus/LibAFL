# Dynamic Analysis Fuzzer
This fuzzer is to show how you can collect runtime analysis information during fuzzing using LibAFL. We use the Little-CMS project for the example.
First, this fuzzer requires `nlohmann-json3-dev` to work.

To run the fuzzer,
0. Compile the fuzzer with `cargo build --release`
1. `mkdir analysis` and run `build.sh`. This will compile Little-CMS to extract the analysis information and generate a json file for each module.
2. run `python3 concatenator.py analysis`. This will concatenate all the json into one single file. This json file maps a function id to its analysis information.
3. Compile the fuzzer with `cargo make fuzzer`. This will instrument the fuzzer at every function entry point. Therefore, whenever we reach the entry of any function, we 
can log its id and logs what functions we executed.
4. Run the fuzzer `RUST_LOG=info ./fuzzer --input ./corpus --output ./out`. You'll see a stream of analysis data 
# How to use python bindings
## First time setup
```bash
# Install maturin
pip install maturin
# Create virtual environment
python3 -m venv .env
```
## Build bindings
```
# Activate virtual environment
source .env/bin/activate
# Build python module
maturin develop
```
This is going to install `pylibafl` python module into this venv. 

## Use bindings
### Example: Running baby_fuzzer in fuzzers/baby_fuzzer/baby_fuzzer.py
First, make sure the python virtual environment is activated. If not, run `source .env/bin/activate
`. Running `pip freeze` at this point should display the following (versions may differ):
```
maturin==0.12.6
pylibafl==0.7.0
toml==0.10.2
```
Then simply run
```
python PATH_TO_BABY_FUZZER/baby_fuzzer.py
```
The crashes directory will be created in the directory from which you ran the command.

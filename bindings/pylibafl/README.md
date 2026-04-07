# How to use python bindings

## First time setup

```bash
# Navigate to the pylibafl directory
cd LibAFL/bindings/pylibafl
# Create virtual environment
python3 -m venv .env
# Activate virtual environment
source .env/bin/activate
# Install dependencies
pip install maturin distlib patchelf
# Build python module
maturin develop
```

This is going to install `pylibafl` python module into this venv.

## Use bindings

### Example: Running the test fuzzer

First, make sure the python virtual environment is activated. If not, run `source .env/bin/activate
`. Running `pip freeze` at this point should display the following (versions may differ):

```ini
distlib==0.4.0
maturin==1.12.6
patchelf==0.17.2.4
pylibafl==0.7.0
```

Then simply run

```sh
./test.sh
```

You should see the following show up after a short pause:

```
Starting to fuzz from python!
PylibAFL works!
```

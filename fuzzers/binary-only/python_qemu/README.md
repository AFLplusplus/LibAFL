# Python LibAFL QEMU

## Build

First, install python bindings (check `LibAFL/bindings/pylibafl`) and use the virtual environment.

Then, create the `in` folder and put some input inside
```bash
$ mkdir in
$ echo aaaaa > in/input
```

## Run

```bash
$ python fuzzer.py
```

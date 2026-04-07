# Python LibAFL QEMU

## Build

First, install python bindings (check `LibAFL/bindings/pylibafl`) and use the virtual environment.

Then, install lief.
```bash
$ pip install lief
```

Then, create the `in` folder and put some input inside
```bash
$ mkdir in
$ echo aaaaa > in/input
```

Finally, compile the binary.
```bash
$ gcc fuzz.c -o a.out
```

## Run

```bash
$ python fuzzer.py
```

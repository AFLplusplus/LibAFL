## Prerequisites
```bash
sudo apt install libsqlite3-dev
```

# Injection test setup

To build the injection test target:
`make`

To run qemu_launcher with the injection detection activated:

```
target/x86_64/release/qemu_launcher -j injections.yaml -i in -o out -- injection_test/static
```

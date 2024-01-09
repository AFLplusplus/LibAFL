# Injection test setup

To build the injection test target:
`make`

To run qemu_launcher with the injection detection activated:

```
target/release/qemu_launcher -y injections.yaml -i in -o out -- injection_test/static
```

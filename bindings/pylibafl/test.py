import pylibafl.sugar as sugar
import ctypes
import platform

print("Starting to fuzz from python!")
fuzzer = sugar.InMemoryBytesCoverageSugar(
    input_dirs=["./in"], output_dir="out", broker_port=1337, cores=[0, 1]
)
fuzzer.run(lambda b: print("foo"))

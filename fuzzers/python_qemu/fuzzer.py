# from the maturin venv, after running 'maturin develop' in the pylibafl directory

from pylibafl import sugar, qemu
import lief

MAX_SIZE = 0x100
BINARY_PATH = './a.out'

qemu.init(['qemu-x86_64', BINARY_PATH], [])

elf = lief.parse(BINARY_PATH)
test_one_input = elf.get_function_address("LLVMFuzzerTestOneInput")
if elf.is_pie:
    test_one_input += qemu.load_addr()
print('LLVMFuzzerTestOneInput @ 0x%x' % test_one_input)

qemu.set_breakpoint(test_one_input)
qemu.run()

sp = qemu.read_reg(qemu.amd64.Rsp)
print('SP   = 0x%x' % sp)

retaddr = int.from_bytes(qemu.read_mem(sp, 8), 'little')
print('RET  = 0x%x' % retaddr)

inp = qemu.map_private(0, MAX_SIZE, qemu.mmap.ReadWrite)
assert(inp > 0)

qemu.remove_breakpoint(test_one_input)
qemu.set_breakpoint(retaddr)

def harness(b):
    if len(b) > MAX_SIZE:
        b = b[:MAX_SIZE]
    qemu.write_mem(inp, b)
    qemu.write_reg(qemu.amd64.Rsi, len(b))
    qemu.write_reg(qemu.amd64.Rdi, inp)
    qemu.write_reg(qemu.amd64.Rsp, sp)
    qemu.write_reg(qemu.amd64.Rip, test_one_input)
    qemu.run()

fuzz = sugar.QemuBytesCoverageSugar(['./in'], './out', 3456, [0,1,2,3])
fuzz.run(harness)

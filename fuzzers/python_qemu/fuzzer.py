# from the maturin venv, after running 'maturin develop' in the pylibafl directory

from pylibafl import sugar, qemu
import lief

RSI = 4
RDI = 5
RSP = 7
RIP = 8

BINARY_PATH = './a.out'

qemu.init(['qemu-x86_64', BINARY_PATH], [])

elf = lief.parse(BINARY_PATH)
test_one_input = elf.get_function_address("LLVMFuzzerTestOneInput")
if elf.is_pie:
    test_one_input += qemu.load_addr()
print('LLVMFuzzerTestOneInput @ 0x%x' % test_one_input)

qemu.set_breakpoint(test_one_input)
qemu.run()

buf = qemu.read_reg(RDI)
size = qemu.read_reg(RSI)
sp = qemu.read_reg(RSP)
print('buf  = 0x%x' % buf)
print('size = 0x%x' % size)
print('SP   = 0x%x' % sp)

retaddr = int.from_bytes(qemu.read_mem(sp, 8), 'little')
print('RET  = 0x%x' % retaddr)

qemu.remove_breakpoint(test_one_input)
qemu.set_breakpoint(retaddr)

def harness(b):
    if len(b) > size:
        b = b[:size]
    qemu.write_mem(buf, b)
    qemu.write_reg(RSI, size)
    qemu.write_reg(RDI, buf)
    qemu.write_reg(RSP, sp)
    qemu.write_reg(RIP, test_one_input)
    qemu.run()

fuzz = sugar.QemuBytesCoverageSugar(['./in'], './out', 3456, [0,1,2,3])
fuzz.run(harness)

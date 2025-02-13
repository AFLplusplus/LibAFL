# from the maturin venv, after running 'maturin develop' in the pylibafl directory

from pylibafl import sugar, qemu
import lief

MAX_SIZE = 0x100
BINARY_PATH = "./a.out"

emu = qemu.Qemu(["qemu-x86_64", BINARY_PATH], [])

elf = lief.parse(BINARY_PATH)
test_one_input = elf.get_function_address("LLVMFuzzerTestOneInput")
if elf.is_pie:
    test_one_input += emu.load_addr()
print("LLVMFuzzerTestOneInput @ 0x%x" % test_one_input)

emu.set_breakpoint(test_one_input)
emu.run()

sp = emu.read_reg(qemu.regs.Rsp)
print("SP   = 0x%x" % sp)

retaddr = int.from_bytes(emu.read_mem(sp, 8), "little")
print("RET  = 0x%x" % retaddr)

inp = emu.map_private(0, MAX_SIZE, qemu.mmap.ReadWrite)
assert inp > 0

emu.remove_breakpoint(test_one_input)
emu.set_breakpoint(retaddr)


def harness(b):
    if len(b) > MAX_SIZE:
        b = b[:MAX_SIZE]
    emu.write_mem(inp, b)
    emu.write_reg(qemu.regs.Rsi, len(b))
    emu.write_reg(qemu.regs.Rdi, inp)
    emu.write_reg(qemu.regs.Rsp, sp)
    emu.write_reg(qemu.regs.Rip, test_one_input)
    emu.run()


fuzz = sugar.QemuBytesCoverageSugar(["./in"], "./out", 3456, [0, 1, 2, 3])
fuzz.run(emu, harness)

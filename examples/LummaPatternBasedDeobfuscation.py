# Licensed under Apache 2.0
#
# Lumma features a lot of obfuscation techniques. This script tackles the
# following, which the most problematic as it obfuscates the control flow:
# 
# 8b 04 85 18 6b 44 00  MOV  EAX, dword ptr [EAX*0x4 + DAT_00446b18]
# b9 e4 b2 85 35        MOV  ECX, 0x3585b2e4
# 33 0d 20 6b 44 00     XOR  ECX, dword ptr [DAT_00446b20]
# 01 c1                 ADD  ECX, EAX
# 41                    INC  ECX
# 31 c0                 XOR  EAX, EAX
# ff e1                 JMP  ECX
#
# At the start of this pattern, EAX may be either 0 or 1, so this works as an if-else
# statement. But getting this right is hard for decompilers, including Ghidra, so
# we need to give her a hand.
#
# This script looks for that byte pattern (with wildcard for constants and registers),
# then emulates the statement for eax=0 and for eax=1, and finally replaces the
# whole code block with a functionally equivalent short patch (TEST / JZ / JMP).

from ghidralib import *

pattern = "8B 04 85 ?? ?? ?? ?? b? ?? ?? ?? ?? 3? ?? ?? ?? ?? ?? 01 ?? 4?"
for addr in findall_pattern(pattern):
    # There may be instructions before the JMP, so let's disassemble next 10 instructions
    # and find the JMP (to get the register that the JMP jumps to)
    for op in disassemble_at(addr, 10):
        if op.mnemonic == "JMP":
            jump_to = op.operands[0]
            break
    else:
        raise RuntimeError("No JMP found")

    # Emulate what happens if EAX=0
    emu = Emulator()
    emu.emulate(addr, op.address)
    iffalse = emu[jump_to]

    # Emulate what happens if EAX=1
    emu = Emulator()
    emu["eax"] = 1
    emu.emulate(addr, op.address)
    iftrue = emu[jump_to]

    # Write the patch (and pad the rest of the block with NOPs)
    assemble_at(addr, [
        "TEST EAX, EAX",
        "JZ 0x{:x}".format(iffalse),
        "JMP 0x{:x}".format(iftrue),
    ], pad_to=op.address - addr + 2)

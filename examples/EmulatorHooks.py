# Licensed under Apache 2.0
#
# Example of basic support for emulator hooks.
#
# A better support (with automated parameter and return handling) will come later.

from ghidralib import *


def printf(emu):
    # Hook function gets emulator as parameter, and returns a "should_continue" bool.
    arg = emu.read_cstring(emu["rsi"])
    print("printf called with '{}'".format(arg))
    # Execute a RET operation manually
    emu.pc = emu.read_u64(emu.sp)
    emu.sp += 8
    return True


e = Emulator()
e.add_hook("__printf_chk", printf)
# Note - add_hook takes an address. Here we take advantage of ghidralib feature that
# (almost) everywhere where you can put address, you can use symbol name and it will
# be automatically resolved to its address.

main = Function("main")
e.emulate(main.entrypoint, main.exitpoints)
print("Main returned {}".format(e["rax"]))

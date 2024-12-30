# Licensed under Apache 2.0
#
# Recover parameters passed to a function at a call site.
# This uses Ghidra emulator to emulate a current basic block up to the
# call opcode, and gets the context at the call location. Since the malware
# was written in Delphi, first three parameters are passed in registers which
# makes our job easy.

from ghidralib import *


# Recovered by reverse-engineering
KEY = unhex("21 aa eb d3 48 de a8 92 06 26 44 b1 e7 85 1a b4")


def decode(dat):
    """String obfuscation used by the analysed malware"""
    l, r = dat[::2], dat[1::2]
    offset = 16 - len(dat) % 16
    return xor(KEY, r) + xor(KEY[::-1][offset:], l)[::-1]


for call in Function("MyCustomCrypto").calls:
    ctx = call.infer_context()
    key, data = ctx["eax"], ctx["edx"]
    if key and data:
        datalen = read_u32(data - 4)
        print(call.address, decode(read_bytes(data, datalen)))

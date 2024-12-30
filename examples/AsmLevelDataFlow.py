# Licensed under Apache 2.0
#
# Perform a simple data flow analysis on x86 instructions. The assembly code looks like this:
#
# 004d47f0 8d 0d f2 c2 5f 00  LEA        ECX,[gos_AdjustTokenPrivileges_5fc2f2]                       = "AdjustTokenPrivileges"
# 004d47f6 89 08              MOV        dword ptr [EAX],ECX=>gos_AdjustTokenPrivileges_5fc2f2        = "AdjustTokenPrivileges"
# 004d47f8 8b 0d 70 a8 7d 00  MOV        ECX,dword ptr [DAT_007da870]
# 004d47fe 85 c9              TEST       ECX,ECX
# 004d4800 75 08              JNZ        LAB_004d480a
# 004d4802 89 05 30 32 7b 00  MOV        dword ptr [DAT_5fc2f2],EAX
#
# And this snippet repeats dozens (or hundreds) of times in a single function.
# This script looks for the "LEA ECX, [source]" instructions followed later
# by "MOV [target], EAX" and renames the [target] to "ptr_{Symbol(source).name}".
# So in this case, this will rename DAT_5fc2f2 to "ptr_gos_AdjustTokenPrivileges_5fc2f2".
#
# This is not the best kind of analysis (a proper symbolic execution would be better),
# but it's good for quick scripts that only need to work once, because it's easy to
# understand and write.
#
# Tested on 3505cd623ee88e3d396789bbe93ebce9834a72f73c9f335fb490924a71a3b21b

from ghidralib import *

f = Function(0x004d47f0)

last_pointer = 0
for op in f.instructions:
    if op.mnemonic == "LEA" and op.operand(0) == "ECX":
        # Operands are ["ECX", [0xAAAAAAAA]], where 0xAAAAAAAA is a pointer to string
        last_pointer = op.scalar(1)
    elif op.mnemonic == "MOV" and isinstance(op.operand(0), (int, long)):
        # Operands are [[0xBBBBBBBB], "EAX"], where 0xBBBBBBBB is the target variable
        target = op.scalar(0)
        ptrname = Symbol(last_pointer).name
        print("detected move of {} to {:x}".format(ptrname, target))
        Symbol.create(target, "ptr_{}".format(ptrname))

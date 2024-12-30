# Licensed under Apache 2.0
#
# Decompile the function at the cursor and output the highlevel Pcode (PcodeAST)
#
# Basically this: https://github.com/evm-sec/high-pcode/blob/main/HighPCode.java
# but in 4 lines of code instead of 103

from ghidralib import *

func = Function(Program.location())
for op in func.high_pcode:
    print(op)

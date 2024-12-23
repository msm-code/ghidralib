# Licensed under Apache 2.0
#
# At the beginning there was this:
#
# void InitDynamicFunctions(void) {
#   DAT_00400010 = FUN_040b886;
#   DAT_00400014 = FUN_040b91c;
#   DAT_00400018 = FUN_040ba20;
#   DAT_0040001C = FUN_040bc20;
#
# Each of the functions was later used to dynamically load and execute a function -
# so they worked as lazy function pointers. This script automatically processes such
# function, and renames all symbols (by decompiling FUN_040ba... and checking
# the referenced string literals). The end result is this:
#
# void InitDynamicFunctions(void) {
#   var_accept = load_accept;
#   var_bind = load_bind;
#   var_closesocket = load_closesocket;
#   var_connect = load_connect;
#
# this script also retypes involved variables by looking up the appropriate pointer type..

from ghidralib import *

for instruction in Function("InitDynamicFunctions").instructions:
    if instruction.mnemonic != "MOV":
        continue

    to, frm = instruction.operands
    func = Function.get(frm)
    if not func:
        func = Function.create(frm, "tmp_func")

    for op in func.high_pcode:
        if op.opcode != op.COPY:
            continue

        literal = get_string(op.inputs[0].value)
        if not literal:
            continue

        print("renaming {:x} based on literal {}".format(func.entrypoint, literal))
        func.rename("load_{}".format(literal))
        label = Symbol.create(to, "var_{}".format(literal))
        functype = DataType.get(literal)
        if functype:
            label.set_type(functype)
        break

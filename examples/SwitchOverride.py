# Original IP: GHIDRA (SwitchOverride.java)
#   rewritten to Python by msm
# Licensed under Apache 2.0
#
# Override a jump opcode so it jumps to the computed jump.
#
# Usage:
# 1. Add the COMPUTED_JUMP references to the branch instruction manually
# 2. run the script when cursor is over the branch instruction

from ghidralib import *


def is_computed_branch(inst):  # type: (Instruction) -> bool
    if inst.flow_type.is_jump and inst.flow_type.is_computed:
        return True

    if inst.flow_type.is_call:
        for xref in inst.xrefs_from:
            if xref.is_call:
                func = Function.get(xref.to_address)
                if func and func.fixup:
                    return True

    return False


def switch_override(addr):  # type: (Addr) -> None
    inst = Instruction(addr)
    if not is_computed_branch(inst):
        print("Please highlight or place the cursor on the instruction performing the computed jump.")  # fmt: skip
        return

    destlist = [xref.to_address for xref in inst.xrefs_from if xref.is_jump]
    if not destlist:
        print("Please highlight destination instructions too.")  # fmt: skip
        return

    func = Function.get(addr)
    if not func:
        print("Computed jump instruction must be in a Function body.")
        return

    # At some point, jumptables were integrated into ghidralib core - so this
    # code is now trivial. Internally this is implemented as a few lines
    # of code that create a JumpTable object and write it.
    inst.write_jumptable(destlist)

switch_override(Program.location())

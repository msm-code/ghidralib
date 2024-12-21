# Original IP: GHIDRA (SwitchOverride.java)
#   rewritten to Python by msm
# Licensed under Apache 2.0
#
# Override a jump opcode so it jumps to the computed jump.
#
# Usage:
# 1. Add the COMPUTED_JUMP references to the branch instruction manually
# 2. run the script when cursor is over the branch instruction
# //@category Repair

from ghidralib import *


def is_computed_branch(inst):  # type: (Instruction) -> bool
    if inst.flow.is_jump and inst.flow.is_computed:
        return True

    if inst.flow.is_call:
        for xref in inst.xrefs_from:
            if xref.is_call:
                func = get_function(xref.to_address)
                if func and func.fixup:
                    return True

    return False


def switch_override(addr):  # type: (Addr) -> None
    inst = Instruction(addr)
    if not is_computed_branch(inst):
        print("Please highlight or place the cursor on the instruction performing the computed jump")  # fmt: skip
        return

    destlist = [xref.to_address for xref in inst.xrefs_from if xref.is_jump]
    if not destlist:
        print("Please highlight destination instructions in addition to instruction performing switch")  # fmt: skip
        print(" Or put CONDITIONAL_JUMP destination references at the branching instruction")  # fmt: skip
        return

    func = get_function(addr)
    if not func:
        print("Computed jump instruction must be in a Function body.")
        return

    for dest in destlist:
        inst.add_operand_reference(
            0, dest, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED
        )

    # And now just fall-back to java
    from ghidra.program.model.pcode import JumpTable
    from ghidra.app.cmd.function import CreateFunctionCmd
    from java.util import ArrayList

    jumpTab = JumpTable(toAddr(addr), ArrayList(toAddr(d) for d in destlist), True)
    jumpTab.writeOverride(func)
    CreateFunctionCmd.fixupFunctionBody(currentProgram, func.raw, monitor)


switch_override(current_location())

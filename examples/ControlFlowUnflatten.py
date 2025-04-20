from ghidralib import PcodeOp, Program, HighFunction, Varnode


def is_state_var(state_var, var, depth = 0):  # type: (Varnode, Varnode) -> bool
    if depth > 1:
        return False

    if var.is_unique:
        var_def = var.defining_pcodeop
        if var_def.opcode == PcodeOp:
            var = var_def.inputs[0]
        elif var_def.opcode == PcodeOp.MULTIEQUAL:
            for input_var in var_def.inputs:
                if is_state_var(state_var, input_var, depth + 1):
                    return True
    
    return state_var == var


def find_state_var(high_func, addr):  # type: (HighFunction, int) -> Varnode
    op = None
    for op in high_func.get_pcode_at(addr):
        if op.opcode == PcodeOp.COPY and op.inputs[0].is_constant:
            break

    assert op is not None, "Can't find a COPY at the current address"
    depth = 0
    while op is not None and op.opcode != PcodeOp.MULTIEQUAL:
        assert op.output is not None, "Opcode output is None"
        op = op.output.lone_descend
        depth += 1
        if depth >= 10:
            break
    
    assert op is not None and op.opcode == PcodeOp.MULTIEQUAL, "Can't find Phi node"

    state_var = op.output
    assert state_var is not None, "Phi node with no output"
    return state_var


def get_const_map(high_func, state_var):  # type(HighFunction, Varnode) -> None
    const_map = {}

    for block in high_func.basicblocks:
        if len(block.out_edges) != 2:
            continue
        
        last_pcode = block.pcode[-1]
        if last_pcode.opcode != PcodeOp.CBRANCH:
            print(2)
            continue

        condition = last_pcode.inputs[1]
        condition_pcode = condition.defining_pcodeop
        condition_type = condition_pcode.opcode
        if condition_type not in (PcodeOp.INT_NOTEQUAL, PcodeOp.INT_EQUAL):
            print(3)
            continue
        
        in0, in1 = condition_pcode.inputs
        if in0.is_constant:
            const_var, compared_var = in0, in1
        elif in1.is_constant:
            const_var, compared_var = in1, in0
        else:
            print(4)
            continue
        
        if not is_state_var(state_var, compared_var):
            print(5)
            continue

        if condition_type == PcodeOp.INT_NOTEQUAL:
            const_map[const_var.value] = block.false_out
        else:
            const_map[const_var.value] = block.true_out

    return const_map


def main():
    high_func = HighFunction(Program.location())
    state_var = find_state_var(high_func, Program.location())
    print(state_var)
    const_map = get_const_map(high_func, state_var)
    print(const_map)


main()
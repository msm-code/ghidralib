from ghidralib import PcodeOp, Program, HighFunction, Varnode, read_u32, read_u64


def is_state_var(state_var, var, depth = 0):  # type: (Varnode, Varnode, int) -> bool
    if depth > 1:
        return False

    if var.is_unique:
        var_def = var.defining_pcodeop
        assert var_def is not None, "Varnode with no associated PcodeOp encountered"
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
            continue

        condition = last_pcode.inputs[1]
        condition_pcode = condition.defining_pcodeop
        condition_type = condition_pcode.opcode
        if condition_type not in (PcodeOp.INT_NOTEQUAL, PcodeOp.INT_EQUAL):
            continue
        
        in0, in1 = condition_pcode.inputs
        if in0.is_constant:
            const_var, compared_var = in0, in1
        elif in1.is_constant:
            const_var, compared_var = in1, in0
        else:
            continue
        
        if not is_state_var(state_var, compared_var):
            continue

        if condition_type == PcodeOp.INT_NOTEQUAL:
            const_map[const_var.value] = block.false_out
        else:
            const_map[const_var.value] = block.true_out

    return const_map


def find_const_def_blocks(var_size, pcode, depth, result, def_block):
    if depth > 3:
        return
    
    if pcode is None:
        return
    
    if pcode.opcode == PcodeOp.COPY:
        input_var = pcode.inputs[0]
        if def_block is None:
            def_block = pcode.parent
        if input_var.is_constant:
            if def_block not in result:
                result[def_block] = input_var.value
        elif input_var.is_address:
            if var_size == 4:
                ram_value = read_u32(input_var.value)
                result[def_block] = ram_value
            elif var_size == 8:
                ram_value = read_u64(input_var.value)
                result[def_block] = ram_value
        else:
            find_const_def_blocks(var_size, input_var.defining_pcodeop, depth + 1, result, def_block)
    elif pcode.opcode == PcodeOp.MULTIEQUAL:
        for input_var in pcode.inputs:
            find_const_def_blocks(var_size, input_var.defining_pcodeop, depth + 1, result, def_block)


def find_var_definitions(var):  # type: (Varnode) -> dict
    phi = var.defining_pcodeop
    assert phi is not None, "Variable has no associated PcodeOp"
    var_defs = {}
    for var_def in phi.inputs:
        if var_def == var:
            continue
        pcode = var_def.defining_pcodeop
        find_const_def_blocks(var.size, pcode, 0, var_defs, None)

    return var_defs


def generate_control_flow(const_map, var_defs):
    links = []

    for def_block, const in var_defs.items():
        if len(def_block.outputs) == 1:
            # Unconditional jump
            if const in const_map:
                links.append((def_block, const_map[const]))
        elif len(def_block.outputs) == 2:
            # Conditional jumps
            true_out, false_out = def_block.true_out, def_block.false_out
            if true_out in var_defs:
                true_const = var_defs[true_out]
                if true_const not in const_map:
                    continue
                true_block = const_map[true_const]

                #...

                if false_out in state_var_def:
                    # ...
                if const not in const_map:
                    continue
                false_block = const_map[const]

                # false
            elif false_out in var_defs
                false_const = var_defs[false_out]
                if false_const not in const_map:
                    continue
                false_block = const_map[false_const]
                if const not in const_map:
                    continue
                true_block = const_map[const]
                links.append((def_block, true_block, false_block))


def main():
    high_func = HighFunction(Program.location())
    state_var = find_state_var(high_func, Program.location())
    print(state_var)
    const_map = get_const_map(high_func, state_var)
    print(const_map)
    state_var_defs = find_var_definitions(state_var)
    print(state_var_defs)
    cfg = generate_control_flow(const_map, state_var_defs)
    print(cfg)



main()

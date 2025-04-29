from ghidralib import PcodeOp, Program, HighFunction, Varnode, assemble_at, read_u32, read_u64, Instruction, RefType, PcodeBlock


def is_assigned_from(target, source, depth = 0):  # type: (Varnode, Varnode, int) -> bool
    """Check if target is assigned from source, directly or via MULTIEQUAL operation"""
    if depth > 1:
        return False

    if source.is_unique:
        source_op = source.defining_op
        if source_op.opcode == PcodeOp.COPY:
            source = source_op.inputs[0]
        elif source_op.opcode == PcodeOp.MULTIEQUAL:
            for input_var in source_op.inputs:
                return is_assigned_from(target, input_var, depth + 1)

    return target == source


def find_state_var(high_func, addr):  # type: (HighFunction, int) -> Varnode
    """Find a Varnode that is used to dispatch the control flow in the function"""
    op = None
    for op in high_func.get_pcode_at(addr):
        if op.opcode == PcodeOp.COPY and op.inputs[0].is_constant:
            break

    if op is None or op.output is None:
        raise RuntimeError("Can't find a COPY at the current address")

    depth = 0
    while op.opcode != PcodeOp.MULTIEQUAL:
        op = op.output.lone_descend
        depth += 1
        if op is None or op.output is None or depth >= 10:
            raise RuntimeError("Can't find a Phi node")

    return op.output


def get_const_map(high_func, state_var):  # type: (HighFunction, Varnode) -> dict[int, PcodeBlock]
    """Construct a map of [constant] -> [pcode block that it leads to]"""
    const_map = {}
    for block in high_func.basicblocks:
        last_pcode = block.pcode[-1]
        if len(block.out_edges) == 2 and last_pcode.opcode == PcodeOp.CBRANCH:
            condition = last_pcode.inputs[1].defining_op

            in0, in1 = condition.inputs
            if in0.is_constant:
                const_var, compared_var = in0, in1
            elif in1.is_constant:
                const_var, compared_var = in1, in0
            else:
                continue

            if is_assigned_from(state_var, compared_var):
                if condition.opcode == PcodeOp.INT_NOTEQUAL:
                    const_map[const_var.value] = block.false_out
                elif condition.opcode == PcodeOp.INT_NOTEQUAL:
                    const_map[const_var.value] = block.true_out

    return const_map


def find_const_def_blocks(var_size, pcode, depth, result, def_block):  # type: (int, PcodeOp, int, dict[PcodeBlock, int], PcodeBlock|None) -> None
    if depth > 3:
        return
    
    if pcode.opcode == PcodeOp.COPY:
        input_var = pcode.inputs[0]
        if def_block is None:
            def_block = pcode.parent
        if input_var.is_constant:
            if def_block not in result:
                assert input_var.value is not None
                result[def_block] = input_var.value
        elif input_var.is_address:
            if var_size == 4:
                ram_value = read_u32(input_var.value)
                result[def_block] = ram_value
            elif var_size == 8:
                ram_value = read_u64(input_var.value)
                result[def_block] = ram_value
        else:
            find_const_def_blocks(var_size, input_var.defining_op, depth + 1, result, def_block)
    elif pcode.opcode == PcodeOp.MULTIEQUAL:
        for input_var in pcode.inputs:
            find_const_def_blocks(var_size, input_var.defining_op, depth + 1, result, def_block)


def find_var_definitions(var):  # type: (Varnode) -> dict[PcodeBlock, int]
    phi = var.defining_op
    var_defs = {}
    for var_def in phi.inputs:
        if var_def == var:
            continue
        find_const_def_blocks(var.size, var_def.defining_op, 0, var_defs, None)

    return var_defs


def generate_control_flow(const_map, var_defs):  # type: (dict[int, PcodeBlock], dict[PcodeBlock, int]) -> list
    links = []
    cmovs = []
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

                if false_out in var_defs:
                    false_const = var_defs[false_out]
                    if false_const not in const_map:
                        continue
                    false_block = const_map[false_const]
                elif const in const_map:
                    false_block = const_map[const]
                else:
                    continue
                links.append((def_block, true_block, false_block))
                cmovs.append(true_out)
            elif false_out in var_defs:
                false_const = var_defs[false_out]
                if false_const not in const_map:
                    continue
                false_block = const_map[false_const]
                if const not in const_map:
                    continue
                true_block = const_map[const]
                links.append((def_block, true_block, false_block))

    return [link for link in links if link[0] not in cmovs]


def patch_x86(cfg):
    for link in cfg:
        block, targets = link[0], link[1:]
        instr = Instruction(block.stop)
        if len(targets) == 1:
            target = targets[0].start
            instr.add_operand_reference(0, target, RefType.JUMP_OVERRIDE_UNCONDITIONAL)
            for xref in instr.xrefs_from:
                if xref.reftype == RefType.JUMP_OVERRIDE_UNCONDITIONAL:
                    xref.set_primary()
            print("{:x} --> {:x}".format(instr.address, target))
        if len(targets) == 2:
            true_addr, false_addr = targets[0].start, targets[1].start
            asm = [
                "{} 0x{:x}".format(instr.mnemonic.replace('CMOV', 'J'), true_addr),
                "JMP 0x{:x}".format(false_addr),
            ]
            assemble_at(instr.address, asm)
            print("{:x}: {}".format(instr.address, asm))


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
    patch_x86(cfg)



main()

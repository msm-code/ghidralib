from ghidralib import PcodeOp, Program, HighFunction, Varnode


def find_state_var(high_func, addr):  # type: (HighFunction, int) -> Varnode
    op = None
    for op in high_func.get_pcode_at(addr):
        if op.opcode == PcodeOp.COPY and op.inputs[0].is_constant:
            break

    print("COPY opcode: {}".format(op))
    if op is None:
        raise RuntimeError("Can't find a COPY opcode at current address")

    depth = 0
    while op is not None and op.opcode != PcodeOp.MULTIEQUAL:
        print("Looking for a phi node: {}, depth {}".format(op, depth))
        if op.output is None:
            raise RuntimeError("Failed: Opcode output is None")
        op = op.output.lone_descend
        depth += 1
        if depth >= 10:
            break
    
    if op is None or op.opcode != PcodeOp.MULTIEQUAL:
        raise RuntimeError("Failed: Can't find Phi node")

    state_var = op.output
    print("Phi node: {}".format(op))
    print("State var: {}".format(state_var))
    return state_var


def main():
    high_func = HighFunction(Program.location())
    state_var = find_state_var(high_func, Program.location())

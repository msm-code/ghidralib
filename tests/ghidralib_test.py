from inspect import ismethod
from ghidralib import *

# Run tests on 44573a7526d5053a28d4e3e70c6ad8adf8eec148d8fe81302140b6bb3df179c0


# TODO: Symbol.remove
# TODO: disassemble_at


###############################################################
# Test Graph
###############################################################


def test_graph():
    graph = Graph.create("name", "description")
    graph.vertex(1)
    graph.vertex(2)
    graph.edge(1, 2)
    assert 1 in graph
    assert graph.has_vertex(1)
    assert 1 in graph.vertices
    assert len(graph) == 2
    assert len(graph.vertices) == 2
    assert graph.vertex_count == 2
    assert len(graph.edges) == 1
    assert graph.edge_count == 1

    assert graph.name == "name"
    assert graph.description == "description"

    assert graph.dfs(1) == {1: None, 2: 1}
    assert graph.bfs(1) == {1: None, 2: 1}
    assert graph.toposort(1) == [2, 1]


###############################################################
# Test HighVariable
###############################################################


def test_high_variable():
    func = Function("entry").high_function
    assert len(func.variables) > 0

    var = func.variables[0]
    assert var.size > 0
    assert var.name is not None
    assert var.data_type is not None
    assert var.symbol is not None
    assert len(var.varnodes) > 0
    assert var.varnode is not None

    _ = var.is_addr_tied
    _ = var.is_free
    _ = var.is_input
    _ = var.is_persistent
    _ = var.is_unaffected


###############################################################
# Test HighSymbol
###############################################################


def test_high_symbol():
    func = Function("entry").high_function
    assert len(func.symbols) > 0

    sym = func.symbols[0]
    assert sym.size > 0
    assert sym.data_type is not None
    _ = sym.variable  # this may be none
    assert sym.name is not None
    _ = sym.symbol  # may be none
    assert not sym.is_this_pointer


###############################################################
# Test register
###############################################################


def test_register():
    assert Register.get("eax") is not None
    assert Register("eax").name == "EAX"


###############################################################
# Test Varnode
###############################################################


def test_varnode():
    func = Function("entry")
    assert len(func.varnodes) > 0
    vn = func.varnodes[0]

    if vn.has_value:
        assert vn.value is not None
    _ = vn.offset
    _ = vn.size
    # _ = vn.high
    # _ = vn.symbol

    _ = vn.is_constant
    _ = vn.is_register
    if vn.is_register:
        assert vn.as_register is not None
    _ = vn.is_address
    _ = vn.is_unique
    _ = vn.is_hash
    _ = vn.is_unaffected
    _ = vn.is_persistent
    _ = vn.is_addr_tied
    _ = vn.is_input
    _ = vn.is_free
    # _ = vn.defining_pcodeop
    _ = vn.descendants

    assert isinstance(vn.simple, (str, unicode, int))
    assert vn.free.is_free


# TODO PcodeBlock
# TODO BlockGraph

###############################################################
# Test HighFunction
###############################################################


def test_high_function():
    foo = HighFunction.get("sado")
    assert foo is None

    # ghidralib sanity
    func = HighFunction("FUN_00406831")
    assert func == HighFunction.get("FUN_00406831")
    assert func == HighFunction.get(0x00406831)
    assert func == HighFunction.get(toAddr(0x00406831))
    assert func == HighFunction.get(func.raw)

    assert len(Function.all()) > 10

    func = HighFunction("entry")
    func.get_pcode_at(0x00406831)  # not throws
    assert len(func.pcode) > 0
    assert len(func.basicblocks) > 0
    assert func.pcode_tree is not None
    assert len(func.symbols) > 0
    assert len(func.variables) > 0


# TODO Reference
# TODO RefType


###############################################################
# Test Instruction
###############################################################


def test_instruction():
    ins = Instruction.get(0x1234)
    assert ins is None

    assert Instruction("entry") == Function("entry").instructions[0]

    ins = Instruction.get(0x406837)
    assert ins is not None

    # ghidralib sanity
    ins = Instruction(0x406837)
    assert ins == Instruction.get(0x406837)
    assert ins == Instruction.get(toAddr(0x406837))
    assert ins == Instruction.get(ins.raw)

    assert ins.mnemonic == "SUB"
    assert ins.address == 0x406837
    assert ins.next == Instruction(0x40683A)
    assert ins.prev == Instruction(0x406834)

    assert len(ins.pcode) > 0
    assert ins.high_pcode is not None

    assert ins.to_bytes() == "\x83\xec\x18"
    assert ins.length == 3
    assert len(ins) == 3
    assert ins.operand(0) == "ESP"
    assert ins.operand(1) == 0x18

    assert ins.operands == ["ESP", 0x18]

    mov = Instruction(0x40683E)
    assert len(mov.xrefs_from) > 0

    # TODO fallthrough_override and jumptable


# TODO AddressRange
# TODO AddressSet

###############################################################
# Test BasicBlock
###############################################################


def test_basic_block():
    block = BasicBlock.get(0x1234)
    assert block is None

    block = BasicBlock(0x004043D9)
    assert block == BasicBlock.get(0x004043D9)
    assert block == BasicBlock.get("FUN_004043d9")
    assert block == BasicBlock.get(toAddr(0x004043D9))
    assert block == BasicBlock.get(block.raw)

    assert block in Function(0x004043D9).basicblocks

    assert block.address == 0x004043D9
    assert block.start_address == 0x004043D9
    assert block.end_address == 0x004043F8

    assert len(block.instructions) > 0
    assert len(block.pcode) > 0
    assert len(block.destinations) > 0
    assert len(block.sources) > 0
    assert block.address in block.body

    assert len(BasicBlock.all()) > 10
    assert len(Program.control_flow()) > 10

    assert block.flow_type is not None


###############################################################
# Test Variable
###############################################################


def test_variable():
    func = Function(0x004043D9)
    vars = func.variables

    assert len(vars) > 0
    var = vars[0]

    assert var.function == func

    assert var.name is not None
    org_name = var.name
    var.rename(org_name + "fun")
    assert var.name == org_name + "fun"
    var.rename(org_name)

    assert var.data_type is not None
    org_type = var.data_type
    var.data_type = DataType("int")
    assert var.data_type.name == "int"
    var.data_type = org_type

    assert var.is_valid
    assert var.comment is None
    var.comment = "x"
    assert var.comment == "x"
    var.comment = None

    # Just call the methods, to make sure they don't raise exceptions
    _ = var.is_stack
    _ = var.is_memory
    _ = var.is_unique
    _ = var.is_compound
    _ = var.is_forced_indirect
    _ = var.has_bad_storage
    _ = var.is_unassigned_storage
    _ = var.is_void
    _ = var.stack_offfset
    _ = var.is_constant
    _ = var.is_hash
    _ = var.is_stack
    _ = var.is_memory
    _ = var.is_unique
    _ = var.is_compound

    assert var.symbol is not None
    assert len(var.varnodes) > 0
    assert var.varnodes[0].raw

    if var.is_register:
        assert var.register is not None


###############################################################
# Test Parameter
###############################################################


def test_parameter():
    func = Function(0x004043D9)
    params = func.parameters

    assert len(params) > 0
    param = params[0]
    assert param.ordinal == 0
    assert param.formal_data_type.name == "int"


###############################################################
# Test FunctionCall
###############################################################


def test_function_call():
    func = Function.get(0x004043D9)
    assert func is not None

    calls = func.calls
    assert len(calls) > 0
    assert any(
        call.calling_function.name == "FUN_004044d1"
        for call in calls
        if call.calling_function
    )
    call = calls[0]

    assert call.called_function.name == func.name
    assert call.address is not None

    assert call.callee == call.called_function
    assert call.caller == call.calling_function

    assert call.high_pcodeop is not None
    assert call.high_pcodeop.raw
    assert len(call.high_pcodeop.inputs) > 1
    assert len(call.high_varnodes) > 0
    assert call.high_varnodes[0].raw
    assert len(call.infer_args()) > 0
    assert call.infer_context() is not None

    assert call.instruction.mnemonic == "CALL"


# TODO ClangTokenGroup


###############################################################
# Test Function
###############################################################


def test_function():
    foo = Function.get("sado")
    assert foo is None

    # ghidralib sanity
    func = Function("FUN_00406831")
    assert func == Function.get("FUN_00406831")
    assert func == Function.get(0x00406831)
    assert func == Function.get(toAddr(0x00406831))
    assert func == Function.get(func.raw)

    assert len(Function.all()) > 10

    func = Function("entry")
    assert func.name == "entry"
    assert func.address == 0x04038AF
    assert func.entrypoint == 0x04038AF
    assert func.return_type.name == "undefined"
    assert not func.is_thunk
    assert not func.is_external

    func.set_comment("x")
    assert func.comment == "x"
    func.set_comment(None)
    assert func.comment is None

    func.set_repeatable_comment("x")
    assert func.repeatable_comment == "x"
    func.set_repeatable_comment("")
    assert func.repeatable_comment == ""

    assert len(func.parameters) == 0
    assert len(func.local_variables) >= 3
    assert func.local_variables[0].raw
    assert len(func.variables) >= 3
    assert func.variables[0].raw
    assert len(func.varnodes) >= 3
    assert func.varnodes[0].raw
    assert len(func.high_variables) >= 3
    assert func.high_variables[0].raw
    assert len(func.stack) > 1
    assert func.stack[0].raw

    func.rename("test")
    assert func.name == "test"
    func.rename("entry")

    assert len(func.xrefs) > 0
    assert func.xrefs[0].raw
    assert len(func.xref_addrs) > 0
    assert len(func.callers) == 0
    assert len(func.called) > 3
    assert func.called[0].raw
    assert len(func.calls) == 0

    func.fixup = "x"
    assert func.fixup == "x"
    func.fixup = None
    assert func.fixup is None

    assert len(func.basicblocks) > 3
    assert func.basicblocks[0].raw
    assert len(func.decompile()) > 100

    assert func.high_function is not None
    assert func.high_function.raw
    assert len(func.get_high_pcode()) > 10
    assert len(func.high_pcode) > 10
    assert func.high_pcode[0].raw

    assert func.pcode_tree is not None

    assert len(func.pcode) > 10
    assert func.pcode[0].raw
    assert len(func.high_basicblocks) > 10
    assert func.high_basicblocks[0].raw

    func.get_high_pcode_at(func.entrypoint)

    assert len(func.high_symbols) > 0
    assert func.high_symbols[0].raw
    assert len(func.primary_symbols) > 0
    assert func.primary_symbols[0].raw
    assert len(func.symbols) > 0
    assert func.symbols[0].raw
    assert not func.body.is_empty
    assert func.body.raw

    assert func.control_flow is not None
    assert func.control_flow.raw


###############################################################
# Test Symbol
###############################################################


def test_symbol():
    sym = Symbol.get("sado")
    assert sym is None

    assert len(Symbol.all()) > 10

    sym = Symbol("FUN_00403caf")
    assert sym.address == 0x00403CAF
    assert sym.name == "FUN_00403caf"
    assert sym.name_with_namespace == "FUN_00403caf"
    assert len(sym.xrefs) > 0
    assert len(sym.xref_addrs) > 0

    sym = Symbol.create(0x00403CDE, "foo")
    assert Symbol.get("foo") is not None
    assert Symbol.get(0x00403CDE) is not None
    sym.rename("bar")
    assert Symbol.get("bar") is not None
    assert sym.name == "bar"

    sym.delete()
    assert Symbol.get("foo") is None
    assert Symbol.get("bar") is None
    assert Symbol.get(0x00403CDE) is None

    assert Symbol("wsprintfA").address == 0xB8AA  # Resolve external address


###############################################################
# Test DataType
###############################################################


def test_datatype():
    dt = DataType.get("sado")
    assert dt is None

    assert len(DataType.all()) > 10
    assert len(DataType.all(True)) < len(DataType.all())

    dt = DataType.get("int")
    assert dt is not None
    assert dt.name == "int"

    dt = DataType.from_c("typedef void* HINTERNET;", insert=False)
    assert dt.name == "HINTERNET"
    assert dt.length == 4


###############################################################
# Test Emulator
###############################################################


def test_emulator():
    emu = Emulator()
    assert emu["esi"] == 0
    emu.emulate(0x403ECB, 0x403ED0)
    assert emu["esi"] == 0xFFFF

    emu["esi"] = 0
    assert emu["esi"] == 0
    assert emu.read_bytes(0x403ECB, 5) != "\x90\x90\x90\x90\x90"
    emu.write_bytes(0x403ECB, "\x90\x90\x90\x90\x90")
    assert emu.read_bytes(0x403ECB, 5) == "\x90\x90\x90\x90\x90"
    emu.emulate(0x403ECB, 0x403ED0)
    # assert emu["esi"] == 0
    # Uhh, looks like Ghidra emulator doesn't support self-modifying code yet.
    # Apparently we're now in a transitional period, and I think we could
    # use AdaptedEmulator instead, but it's scheduled to be deleted.

    emu.write_register("esi", 1)
    assert emu.read_register("esi") == 1

    emu.write_bytes(0x400000, "\x01\x02\x03\x04\x05\x06\x07\x08")
    assert emu.read_u8(0x400000) == 0x01
    assert emu.read_u16(0x400000) == 0x0201
    assert emu.read_u32(0x400000) == 0x04030201
    assert emu.read_u64(0x400000) == 0x0807060504030201

    emu.write_u8(0x400000, 0x01)
    assert emu.read_u8(0x400000) == 0x01
    emu.write_u16(0x400000, 0x0201)
    assert emu.read_u16(0x400000) == 0x0201
    emu.write_u32(0x400000, 0x04030201)
    assert emu.read_u32(0x400000) == 0x04030201
    emu.write_u64(0x400000, 0x0807060504030201)
    assert emu.read_u64(0x400000) == 0x0807060504030201

    assert emu.read_bytes(0x400000, 8) == "\x01\x02\x03\x04\x05\x06\x07\x08"

    # High-level function emulation API
    fnc = Function(0x004061EC)
    emu = fnc.emulate(-0x80000000)
    assert emu.read_unicode(emu["eax"]) == "HKEY_CLASSES_ROOT"

    # Low-level function emulation API
    fnc = Function(0x004061EC)
    emu = Emulator()
    emu.write_varnode(fnc.parameters[0].varnode, -0x80000000)
    emu.emulate_while(fnc.entrypoint, lambda e: e.pc in fnc.body)
    assert emu.read_unicode(emu["eax"]) == "HKEY_CLASSES_ROOT"

    mock_executed = [False]

    def nullsub(emu):
        mock_executed[0] = True
        emu.pc = emu.read_u64(emu.sp)
        emu.sp += 8
        return True

    fun = Function(0x406035)
    emu = Emulator()
    emu.add_hook("lstrcpynW", nullsub)
    emu.emulate(fun.entrypoint, fun.exitpoints)
    assert mock_executed[0]


###############################################################
# Test Program
###############################################################


def test_program():
    assert Program.location() != 0

    cg = Program.call_graph()
    assert len(cg.vertices) == cg.vertex_count
    assert cg.vertex_count > 0
    assert len(cg.edges) == cg.edge_count
    assert cg.edge_count > 0


###############################################################
# Test Utilities
###############################################################


def test_util():
    data = read_bytes(0x0403ED0, 10)
    assert len(disassemble_bytes(data)) > 0
    assert disassemble_bytes(data)[0].mnemonic == "CALL"

    assert disassemble_at(0x0403ED0)[0].mnemonic == "CALL"
    assert len(disassemble_at(0x0403ED0)) == 1
    assert len(disassemble_at(0x0403ED0, max_instr=2)) == 2

    assert assemble_to_bytes(0, ["ADD EAX, EAX", "ADD EAX, EAX"]) == "\x01\xc0\x01\xc0"
    assert assemble_to_bytes(0, "ADD EAX, EAX") == "\x01\xc0"
    # TODO: assemble_at

    assert from_bytes([0x01, 0x02]) == 0x0201
    assert to_bytes(0x0201, 2) == "\x01\x02"
    assert to_bytes(0x0201, 4) == "\x01\x02\x00\x00"
    assert unhex("0102") == "\x01\x02"
    assert enhex("\x01\x02") == "0102"
    assert xor("\x01\x02", "\x03\x04") == "\x02\x06"

    assert get_string(0x40B968) == "ShellExecuteW"
    assert read_cstring(0x40B968) == "ShellExecuteW"


def run():
    for f in globals():
        if f.startswith("test_"):
            print("Running {}...".format(f))
            globals()[f]()
            print("  OK".format(f))
    print("Done!")


run()

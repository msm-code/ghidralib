from inspect import ismethod
from ghidralib import *

# Run tests on 44573a7526d5053a28d4e3e70c6ad8adf8eec148d8fe81302140b6bb3df179c0


# TODO java utils
# TODO Graph
# TODO HighVariable
# TODO HighSymbol
# TODO Register
# TODO Varnode
# TODO PcodeBlock
# TODO BlockGraph

###############################################################
# Test high function
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
# Test instruction
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


# TODO AddressRange
# TODO AddressSet

###############################################################
# Test basic block
###############################################################


def test_basic_block():
    block = BasicBlock.get(0x1234)
    assert block is None

    block = BasicBlock(0x004043D9)
    assert block == BasicBlock.get(0x004043D9)
    assert block == BasicBlock.get("FUN_004043D9")
    assert block == BasicBlock.get(toAddr(0x00406831))
    assert block == BasicBlock.get(block.raw)

    assert block in Function(0x004043D9).basicblocks

    assert block.address == 0x004043D9
    assert block.start_address == 0x004043D9
    assert block.end_address == 0x004043F6

    assert len(block.instructions) > 0
    assert len(block.pcode) > 0
    assert len(block.destinations) > 0
    assert len(block.sources) > 0
    assert block.address in block.body

    assert len(BasicBlock.all()) > 10
    assert len(BasicBlock.program_control_flow()) > 10

    assert block.flow_type is not None


###############################################################
# Test variable
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
    print(var.name)
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

    if var.is_register:
        assert var.register is not None


###############################################################
# Test parameter
###############################################################


def test_parameter():
    func = Function(0x004043D9)
    params = func.parameters

    assert len(params) > 0
    param = params[0]
    assert param.ordinal == 0
    assert param.formal_data_type.name == "int"


###############################################################
# Test function call
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
    assert len(call.high_pcodeop.inputs) > 1
    assert len(call.high_varnodes) > 0
    assert len(call.get_args()) > 0

    assert call.instruction.mnemonic == "CALL"


# TODO ClangTokenGroup


###############################################################
# Test function
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
    assert len(func.local_variables) > 3
    assert len(func.variables) > 3
    assert len(func.varnodes) > 3
    assert len(func.high_variables) > 3
    assert len(func.stack) > 1

    func.rename("test")
    assert func.name == "test"
    func.rename("entry")

    assert len(func.xrefs) > 0
    assert len(func.xref_addrs) > 0
    assert len(func.callers) == 0
    assert len(func.called) > 3
    assert len(func.calls) == 0

    func.fixup = "x"
    assert func.fixup == "x"
    func.fixup = None
    assert func.fixup is None

    assert len(func.basicblocks) > 3
    assert len(func.decompile()) > 100

    assert func.high_function is not None
    assert len(func.get_high_pcode()) > 10
    assert len(func.high_pcode) > 10

    assert func.pcode_tree is not None

    assert len(func.pcode) > 10
    assert len(func.high_pcode) > 10
    assert len(func.high_basicblocks) > 10

    func.get_high_pcode_at(func.entrypoint)

    assert len(func.high_symbols) > 0
    assert len(func.primary_symbols) > 0
    assert len(func.symbols) > 0
    assert not func.body.is_empty

    assert func.control_flow is not None


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
    assert emu.read_memory(0x403ECB, 5) != "\x90\x90\x90\x90\x90"
    emu.write_memory(0x403ECB, "\x90\x90\x90\x90\x90")
    assert emu.read_memory(0x403ECB, 5) == "\x90\x90\x90\x90\x90"
    emu.emulate(0x403ECB, 0x403ED0)

    # assert emu["esi"] == 0
    # Uhh, looks like Ghidra emulator doesn't support self-modifying code yet.
    # Apparently we're now in a transitional period, and I think we could
    # use AdaptedEmulator instead, but it's scheduled to be deleted.

    emu.write_register("esi", 1)
    assert emu.read_register("esi") == 1


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
    assert len(disassemble(data)) > 0
    assert disassemble(data)[0].mnemonic == "CALL"

    assert from_bytes([0x01, 0x02]) == 0x0201
    assert unhex("0102") == "\x01\x02"
    assert enhex("\x01\x02") == "0102"
    assert xor("\x01\x02", "\x03\x04") == "\x02\x06"

    assert get_unique_string(Function("entry")) != ""

    assert get_string(0x40B968) == "ShellExecuteW"
    assert read_cstring(0x40B968) == "ShellExecuteW"


def run():
    test_names = [
        "test_high_function",
        # "test_variable",
        # "test_parameter",
        # "test_instruction",
        "test_basic_block",
        # "test_function_call",
        # "test_function",
        # "test_symbol",
        # "test_datatype",
        # "test_emulator",
        # "test_program",
        # "test_util"
    ]
    for f in test_names:
        if f.startswith("test_"):
            print("Running {}...".format(f))
            globals()[f]()
            print("  OK".format(f))
    print("Done!")


run()

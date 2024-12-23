from ghidralib import *

# Run tests on 44573a7526d5053a28d4e3e70c6ad8adf8eec148d8fe81302140b6bb3df179c0


###############################################################
# Test function
###############################################################


def test_function():
    foo = Function.get("sado")
    assert foo is None

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
    assert emu["esi"] == 0

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
    for f in globals():
        if f.startswith("test_"):
            print("Running {}...".format(f))
            globals()[f]()
            print("  OK".format(f))


run()

"""
This library is an attempt to provide a Pythonic standard library for Ghidra.

The main goal is to make writing quick&dirty scripts actually quick, and not that dirty.

There is no equivalent of FlatProgramAPI from GHidra. You are expected to start
by getting an object of interest by calling instance methods, for example

  >>> Function("main")
  main

to get a function called "main". When you want to do something this library
doesn't support (yet), you can always excape back to Ghidra's wrapped Java
types, by getting a `.raw` property, for example:

  >>> Function("main").raw.UNKNOWN_STACK_DEPTH_CHANGE
  2147483647

For more details, see the documentation at https://msm-code.github.io/ghidralib/.
"""

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.util.cparser.C import CParser
from ghidra.program.model.lang import Register as GhRegister
from ghidra.program.model.pcode import Varnode as GhVarnode
from ghidra.program.model.pcode import BlockGraph as GhBlockGraph, BlockCopy
from ghidra.program.model.block import BasicBlockModel, SimpleBlockModel
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.symbol import RefType as GhRefType
from ghidra.app.emulator import EmulatorHelper
from __main__ import (
    toAddr,
    createFunction,
    getDataAt,
    createLabel,
    state,
    createData,
    clearListing,
    getReferencesTo,
    currentProgram,
    getInstructionAt,
    getBytes,
    currentLocation,
    monitor,
)

try:
    # For static type hints (won't work in Ghidra)
    from typing import Any, Callable, TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False


class JavaObject:
    def __getattribute__(self, name):  # type: (str) -> Any
        pass  # this class exists just for static typing


# Aliases just for typechecking.
if TYPE_CHECKING:
    # Python 2.x archaism.
    long = int

    Addr = GenericAddress | int | str
    # This library accepts one of three things as addressses:
    # 1. A Ghidra Address object
    # 2. An integer representing an address
    # 3. A string representing a symbol name
    # When returning a value, the address is always returned as an integer.

    Reg = GhRegister | str
    # This library accepts one of two things as registers:
    # 1. A Ghidra Register object
    # 2. A string representing a register name


def collect_iterator(iterator):
    result = []
    while iterator.hasNext():
        result.append(iterator.next())
    return result


def resolve(addr):  # type: (Addr) -> GenericAddress
    if isinstance(addr, GenericAddress):
        return addr
    if isinstance(addr, (int, long)):
        return toAddr(addr)
    if isinstance(addr, str):
        return toAddr(Symbol(addr).address)
    print(type(addr))
    raise TypeError("Address must be a ghidra Address, int, or str")


def can_resolve(addr):  # type: (Addr) -> bool
    return isinstance(addr, (GenericAddress, int, long, str))


def unwrap(wrapper_or_java_type):  # type: (JavaObject|GhidraWrapper) -> JavaObject
    if isinstance(wrapper_or_java_type, GhidraWrapper):
        return wrapper_or_java_type.raw
    return wrapper_or_java_type


def _as_javaobject(raw):  # type: (Any) -> JavaObject
    """Ensure the object is actually a Java object, and return it.

    This exists also to make a type-checker happy"""
    assert hasattr(raw, "__class__")
    return raw


class GhidraWrapper:
    def __init__(self, raw):  # type: (JavaObject|int|long|str|GhidraWrapper) -> None
        if isinstance(raw, (int, long, str)):
            # Someone passed a primitive type to us.
            # If possible, try to resolve it with a "get" method.
            if hasattr(self, "get"):
                new_raw = self.get(raw)  # type: ignore
                if new_raw is None:
                    # Show original data for better error messages
                    raise RuntimeError("Unable to wrap " + str(raw))
                raw = new_raw
            else:
                raise RuntimeError("Unable to wrap a primitive: " + str(raw))

        while isinstance(raw, GhidraWrapper):
            # In case someone tries to Function(Function("main")) us
            raw = raw.raw

        if raw is None:
            raise RuntimeError("Object doesn't exist (refusing to wrap None)")

        self.__str__ = raw.__str__
        self.__repr__ = raw.__repr__
        self.raw = _as_javaobject(raw)  # type: JavaObject

    def __tojava__(self, klass):
        """Make it possible to pass this object to Java methods"""
        return self.raw

    def __hash__(self):  # type: () -> int
        return self.raw.hashCode()

    def __eq__(self, other):  # type: (object) -> bool
        if isinstance(other, GhidraWrapper):
            return self.raw.equals(other.raw)
        return self.raw.equals(other)


class HighVariable(GhidraWrapper):
    @property
    def symbol(self):  # type: () -> HighSymbol
        return HighSymbol(self.raw.getSymbol())

    def rename(self, new_name):  # type: (str) -> None
        self.symbol.rename(new_name)


class HighSymbol(GhidraWrapper):
    def rename(self, new_name):  # type: (str) -> None
        HighFunctionDBUtil.updateDBVariable(
            self.raw, new_name, None, SourceType.USER_DEFINED
        )


class Register(GhidraWrapper):
    @property
    def name(self):
        return self.raw.getName()


class Varnode(GhidraWrapper):
    @property
    def has_value(self):  # type: () -> bool
        return self.is_address or self.is_constant

    @property
    def value(self):  # type: () -> int
        """Get the value of this varnode.
        Will raise RuntimeError if varnode doesn't have a constant value.
        Use has_value to check for this before getting the value."""
        if not self.has_value:
            raise RuntimeError("Varnode can't be converted to value")
        return self.raw.getOffset()

    @property
    def offset(self):  # type: () -> int
        return self.raw.getOffset()

    @property
    def size(self):  # type: () -> int
        return self.raw.getSize()

    @property
    def high(self):  # type: () -> HighVariable
        return HighVariable(self.raw.getHigh())

    @property
    def symbol(self):  # type: () -> HighSymbol
        return self.high.symbol

    @property
    def is_constant(self):  # type: () -> bool
        """Note: addresses are not constants in Ghidra-speak.
        Use has_value to check if the varnode has a predictable value."""
        return self.raw.isConstant()

    @property
    def is_register(self):  # type: () -> bool
        return self.raw.isRegister()

    @property
    def is_address(self):  # type: () -> bool
        return self.raw.isAddress()

    @property
    def as_register(self):  # type: () -> Register
        language = currentProgram.getLanguage()
        raw = language.getRegister(self.raw.getAddress(), self.size)
        return Register(raw)

    @property
    def is_unique(self):  # type: () -> bool
        return self.raw.isUnique()

    @property
    def is_hash(self):  # type: () -> bool
        return self.raw.isHash()

    def rename(self, new_name):  # type: (str) -> None
        """Try to rename the current varnode. This only makes sense for variables."""
        self.symbol.rename(new_name)

    @property
    def is_free(self):  # type: () -> bool
        return self.raw.isFree()

    @property
    def free(self):  # type: () -> Varnode
        return Varnode(GhVarnode(self.raw.getAddress(), self.raw.getSize()))

    @property
    def simple(self):  # type: () -> int|str
        """Convert Varnode to a primitive value (int or a string representation)

        More specifically, this will convert constants and addresses into integers,
        for registers names are returned, and for unique and hash varnodes ad-hoc
        string encoding is used (hash:ID or uniq:ID where ID is varnode identifier).

        This is useful for simple analyses when programmer already knows what
        type of value is expected at the given position."""
        if self.has_value:
            return self.value
        elif self.is_register:
            return self.as_register.name
        elif self.is_unique:
            return "uniq:{:x}".format(self.offset)
        elif self.is_hash:
            return "hash:{:x}".format(self.offset)
        raise RuntimeError("Unknown varnode type")


class PcodeOp(GhidraWrapper):
    """Pcode is a Ghidra's low-level intermediate language.
    Instructions from any processor are transformed into PCode
    before any analysis takes place. There is a finite number of
    possible operations.

    While Ghidra doesn't define "High Pcode", this library refers
    to analysed Pcode as "High PCode". While theoretically still
    the same object, Pcode is transformed significantly, for example
    before function parameter analysis "CALL" opcodes have no inputs.
    """

    UNIMPLEMENTED = 0
    COPY = 1
    LOAD = 2
    STORE = 3
    BRANCH = 4
    CBRANCH = 5
    BRANCHIND = 6
    CALL = 7
    CALLIND = 8
    CALLOTHER = 9
    RETURN = 10
    INT_EQUAL = 11
    INT_NOTEQUAL = 12
    INT_SLESS = 13
    INT_SLESSEQUAL = 14
    INT_LESS = 15
    INT_LESSEQUAL = 16
    INT_ZEXT = 17
    INT_SEXT = 18
    INT_ADD = 19
    INT_SUB = 20
    INT_CARRY = 21
    INT_SCARRY = 22
    INT_SBORROW = 23
    INT_2COMP = 24
    INT_NEGATE = 25
    INT_XOR = 26
    INT_AND = 27
    INT_OR = 28
    INT_LEFT = 29
    INT_RIGHT = 30
    INT_SRIGHT = 31
    INT_MULT = 32
    INT_DIV = 33
    INT_SDIV = 34
    INT_REM = 35
    INT_SREM = 36
    BOOL_NEGATE = 37
    BOOL_XOR = 38
    BOOL_AND = 39
    BOOL_OR = 40
    FLOAT_EQUAL = 41
    FLOAT_NOTEQUAL = 42
    FLOAT_LESS = 43
    FLOAT_LESSEQUAL = 44
    # Slot 45 is unused
    FLOAT_NAN = 46
    FLOAT_ADD = 47
    FLOAT_DIV = 48
    FLOAT_MULT = 49
    FLOAT_SUB = 50
    FLOAT_NEG = 51
    FLOAT_ABS = 52
    FLOAT_SQRT = 53
    FLOAT_INT2FLOAT = 54
    FLOAT_FLOAT2FLOAT = 55
    FLOAT_TRUNC = 56
    FLOAT_CEIL = 57
    FLOAT_FLOOR = 58
    FLOAT_ROUND = 59
    MULTIEQUAL = 60
    INDIRECT = 61
    PIECE = 62
    SUBPIECE = 63
    CAST = 64
    PTRADD = 65
    PTRSUB = 66
    SEGMENTOP = 67
    CPOOLREF = 68
    NEW = 69
    INSERT = 70
    EXTRACT = 71
    POPCOUNT = 72
    LZCOUNT = 73
    PCODE_MAX = 74

    @staticmethod
    def get_high_pcode_at(address):  # type: (Addr) -> list[PcodeOp]
        """Get a high pcode for the instruction at a specified address

        Convenience wrapper for Function(address).get_high_pcode_at(address)."""
        return Function(address).get_high_pcode_at(address)

    @property
    def address(self):  # type: () -> int
        """Get an address in the program where this instruction is located"""
        return self.raw.getSeqnum().getTarget().getOffset()

    @property
    def opcode(self):  # type: () -> int
        return self.raw.getOpcode()

    @property
    def mnemonic(self):  # type: () -> str
        """Get a string representation of the operation, for example "COPY" """
        return self.raw.getMnemonic()

    @property
    def inputs(self):  # type: () -> list[Varnode]
        return [Varnode(raw) for raw in self.raw.getInputs()]

    @property
    def inputs_simple(self):  # type: () -> list[int|str]
        """Return inputs as primitive values (int or a string representation).

        More specifically, this will convert constants and addresses into integers,
        for registers names are returned, and for unique and hash varnodes ad-hoc
        string encoding is used (hash:ID or uniq:ID where ID is varnode identifier).
        """
        return [varnode.simple for varnode in self.inputs]

    @property
    def output(self):  # type: () -> Varnode|None
        if self.raw.getOutput() is None:
            return None
        return Varnode(self.raw.getOutput())


def _pcode_node(raw):  # type: (JavaObject) -> PcodeBlock
    """Create a BlockGraph or PcodeBlock, depending on arg type

    This is not technically necessary, but we use it because some people
    (including Ghidra code) use isinstance() checks to dispatch types.
    """
    if isinstance(raw, GhBlockGraph):
        return BlockGraph(raw)
    return PcodeBlock(raw)


class PcodeBlock(GhidraWrapper):
    @property
    def outgoing_edges(self):  # type: () -> list[PcodeBlock]
        return [_pcode_node(self.raw.getOut(i)) for i in range(self.raw.getOutSize())]

    @property
    def incoming_edges(self):  # type: () -> list[PcodeBlock]
        return [_pcode_node(self.raw.getIn(i)) for i in range(self.raw.getInSize())]

    @property
    def is_graph(self):  # type: () -> bool
        return isinstance(self.raw, GhBlockGraph)

    @property
    def pcode(self):  # type: () -> list[PcodeOp]
        raw_pcode = collect_iterator(self.raw.getRef().getIterator())
        return [PcodeOp(raw) for raw in raw_pcode]


class BlockGraph(PcodeBlock):
    @property
    def blocks(self):  # type: () -> list[PcodeBlock]
        return [_pcode_node(self.raw.getBlock(i)) for i in range(self.raw.getSize())]


class HighFunction(GhidraWrapper):
    def get_pcode_at(self, address):  # type: (Addr) -> list[PcodeOp]
        address = resolve(address)
        return [PcodeOp(raw) for raw in self.raw.getPcodeOps(address)]

    @property
    def pcode(self):  # type: () -> list[PcodeOp]
        return [PcodeOp(raw) for raw in self.raw.getPcodeOps()]

    @property
    def basic_blocks(self):  # type: () -> list[PcodeBlock]
        return [PcodeBlock(raw) for raw in self.raw.getBasicBlocks()]

    def get_ast(self):  # type: () -> BlockGraph
        edge_map = {}
        ingraph = GhBlockGraph()
        for block in self.basic_blocks:
            gb = BlockCopy(block.raw, block.raw.getStart())
            ingraph.addBlock(gb)
            edge_map[block.raw] = gb

        for block in self.basic_blocks:
            for edge in block.outgoing_edges:
                ingraph.addEdge(edge_map[block.raw], edge_map[edge.raw])

        ingraph.setIndices()
        decompiler = DecompInterface()
        decompiler.openProgram(currentProgram)
        outgraph = decompiler.structureGraph(ingraph, 0, monitor)
        return BlockGraph(outgraph)


class Reference(GhidraWrapper):
    @property
    def is_call(self):  # type: () -> bool
        return self.reftype.is_call

    @property
    def is_jump(self):  # type: () -> bool
        return self.reftype.is_jump

    @property
    def reftype(self):  # type: () -> RefType
        return RefType(self.raw.getReferenceType())

    @property
    def from_address(self):  # type: () -> int
        return self.raw.getFromAddress().getOffset()

    @property
    def to_address(self):  # type: () -> int
        return self.raw.getToAddress().getOffset()

    # @property
    # def source(self):  # type: () -> SourceType
    #     return SourceType(self.raw.getSource())


def _reftype_placeholder():  # type: () -> RefType
    """Helper to solve the initialization order problem."""
    return None  # type: ignore


class RefType(GhidraWrapper):
    @property
    def has_fall(self):  # type: () -> bool
        return self.raw.hasFallthrough()

    @has_fall.setter
    def has_fall(self, value):  # type: (bool) -> None
        self.raw.setHasFall(value)

    @property
    def is_call(self):  # type: () -> bool
        return self.raw.isCall()

    @is_call.setter
    def is_call(self, value):  # type: (bool) -> None
        self.raw.setIsCall(value)

    @property
    def is_jump(self):  # type: () -> bool
        return self.raw.isJump()

    @is_jump.setter
    def is_jump(self, value):  # type: (bool) -> None
        self.raw.setIsJump(value)

    @property
    def is_computed(self):  # type: () -> bool
        return self.raw.isComputed()

    @is_computed.setter
    def is_computed(self, value):  # type: (bool) -> None
        self.raw.setIsComputed(value)

    @property
    def is_conditional(self):  # type: () -> bool
        return self.raw.isConditional()

    @is_conditional.setter
    def is_conditional(self, value):  # type: (bool) -> None
        self.raw.setIsConditional(value)

    @property
    def is_unconditional(self):  # type: () -> bool
        return not self.is_conditional

    @property
    def is_terminal(self):  # type: () -> bool
        return self.raw.isTerminal()

    @property
    def is_data(self):  # type: () -> bool
        return self.raw.isData()

    @property
    def is_read(self):  # type: () -> bool
        return self.raw.isRead()

    @property
    def is_write(self):  # type: () -> bool
        return self.raw.isWrite()

    @property
    def is_flow(self):  # type: () -> bool
        return self.raw.isFlow()

    @property
    def is_override(self):  # type: () -> bool
        return self.raw.isOverride()

    INVALID = _reftype_placeholder()
    FLOW = _reftype_placeholder()
    FALL_THROUGH = _reftype_placeholder()
    UNCONDITIONAL_JUMP = _reftype_placeholder()
    CONDITIONAL_JUMP = _reftype_placeholder()
    UNCONDITIONAL_CALL = _reftype_placeholder()
    CONDITIONAL_CALL = _reftype_placeholder()
    TERMINATOR = _reftype_placeholder()
    COMPUTED_JUMP = _reftype_placeholder()
    CONDITIONAL_TERMINATOR = _reftype_placeholder()
    COMPUTED_CALL = _reftype_placeholder()
    CALL_TERMINATOR = _reftype_placeholder()
    COMPUTED_CALL_TERMINATOR = _reftype_placeholder()
    CONDITIONAL_CALL_TERMINATOR = _reftype_placeholder()
    CONDITIONAL_COMPUTED_CALL = _reftype_placeholder()
    CONDITIONAL_COMPUTED_JUMP = _reftype_placeholder()
    JUMP_TERMINATOR = _reftype_placeholder()
    INDIRECTION = _reftype_placeholder()
    CALL_OVERRIDE_UNCONDITIONAL = _reftype_placeholder()
    JUMP_OVERRIDE_UNCONDITIONAL = _reftype_placeholder()
    CALLOTHER_OVERRIDE_CALL = _reftype_placeholder()
    CALLOTHER_OVERRIDE_JUMP = _reftype_placeholder()


RefType.INVALID = RefType(GhRefType.INVALID)
RefType.FLOW = RefType(GhRefType.FLOW)
RefType.FALL_THROUGH = RefType(GhRefType.FALL_THROUGH)
RefType.UNCONDITIONAL_JUMP = RefType(GhRefType.UNCONDITIONAL_JUMP)
RefType.CONDITIONAL_JUMP = RefType(GhRefType.CONDITIONAL_JUMP)
RefType.UNCONDITIONAL_CALL = RefType(GhRefType.UNCONDITIONAL_CALL)
RefType.CONDITIONAL_CALL = RefType(GhRefType.CONDITIONAL_CALL)
RefType.TERMINATOR = RefType(GhRefType.TERMINATOR)
RefType.COMPUTED_JUMP = RefType(GhRefType.COMPUTED_JUMP)
RefType.CONDITIONAL_TERMINATOR = RefType(GhRefType.CONDITIONAL_TERMINATOR)
RefType.COMPUTED_CALL = RefType(GhRefType.COMPUTED_CALL)
RefType.CALL_TERMINATOR = RefType(GhRefType.CALL_TERMINATOR)
RefType.COMPUTED_CALL_TERMINATOR = RefType(GhRefType.COMPUTED_CALL_TERMINATOR)
RefType.CONDITIONAL_CALL_TERMINATOR = RefType(GhRefType.CONDITIONAL_CALL_TERMINATOR)
RefType.CONDITIONAL_COMPUTED_CALL = RefType(GhRefType.CONDITIONAL_COMPUTED_CALL)
RefType.CONDITIONAL_COMPUTED_JUMP = RefType(GhRefType.CONDITIONAL_COMPUTED_JUMP)
RefType.JUMP_TERMINATOR = RefType(GhRefType.JUMP_TERMINATOR)
RefType.INDIRECTION = RefType(GhRefType.INDIRECTION)
RefType.CALL_OVERRIDE_UNCONDITIONAL = RefType(GhRefType.CALL_OVERRIDE_UNCONDITIONAL)
RefType.JUMP_OVERRIDE_UNCONDITIONAL = RefType(GhRefType.JUMP_OVERRIDE_UNCONDITIONAL)
RefType.CALLOTHER_OVERRIDE_CALL = RefType(GhRefType.CALLOTHER_OVERRIDE_CALL)
RefType.CALLOTHER_OVERRIDE_JUMP = RefType(GhRefType.CALLOTHER_OVERRIDE_JUMP)


class Instruction(GhidraWrapper):
    def get(self, raw_or_address):  # type: (JavaObject|Addr) -> Instruction
        if can_resolve(raw_or_address):
            raw = getInstructionAt(resolve(raw_or_address))
        else:
            raw = raw_or_address
        return Instruction(raw)

    @property
    def mnemonic(self):  # type: () -> str
        return self.raw.getMnemonicString()

    @property
    def next(self):  # type: () -> Instruction
        return Instruction(self.raw.getNext())

    @property
    def previous(self):  # type: () -> Instruction
        return Instruction(self.raw.getPrevious())

    @property
    def pcode(self):  # type: () -> list[PcodeOp]
        """Get a list of Pcode operations that this instruction was parsed to"""
        return [PcodeOp(raw) for raw in self.raw.getPcode()]

    @property
    def high_pcode(self):  # type: () -> list[PcodeOp]
        """Get high Pcode for this instruction.

        WARNING: do not use this in a loop. Use Function.high_pcode instead."""
        return PcodeOp.get_high_pcode_at(self.address)

    @property
    def xrefs_from(self):  # type: () -> list[Reference]
        return [Reference(raw) for raw in self.raw.getReferencesFrom()]

    def to_bytes(self):  # type: () -> bytes
        return self.raw.getBytes()

    def get_scalar(self, ndx):  # type: (int) -> int
        scalar = self.raw.getScalar(ndx)
        if scalar:
            return scalar.getValue()
        addr = self.raw.getAddress(ndx)
        if addr:
            return addr.getOffset()
        obj = addr.getOpObjects(ndx)
        raise RuntimeError("Can't convert operand {} to scalar", obj)

    @property
    def address(self):  # type: () -> int
        return self.raw.getAddress()

    @property
    def flow(self):  # type: () -> RefType
        return RefType(self.raw.getFlowType())

    # int opIndex, Address refAddr, RefType type, SourceType sourceType
    def add_operand_reference(
        self, op_ndx, ref_addr, ref_type, src_type
    ):  # type: (int, Addr, RefType, SourceType) -> None
        # TODO: wrap SourceType too, someday?
        self.raw.addOperandReference(op_ndx, resolve(ref_addr), ref_type.raw, src_type)


class BasicBlock(GhidraWrapper):
    @staticmethod
    def get(raw_or_address):  # type: (JavaObject|Addr) -> BasicBlock
        """Get a BasicBlock object for the given address, or return None.

        This function is tolerant and will accept different types of arguments:
        * address as int
        * Address object
        * symbol as string (will be resolved)
        * BasicBlock object (wrapped or unwrapped)"""

        if can_resolve(raw_or_address):
            block_model = SimpleBlockModel(currentProgram)
            raw = block_model.getFirstCodeBlockContaining(
                resolve(raw_or_address), TaskMonitor.DUMMY
            )
        else:
            raw = raw_or_address
        return BasicBlock(raw)

    @property
    def start_address(self):  # type: () -> int
        """Get the address of the first instruction in this basic block."""
        return self.raw.getMinAddress().getOffset()

    @property
    def end_address(self):  # type: () -> int
        """Get the address of the last instruction in this basic block."""
        return self.raw.getMaxAddress().getOffset()

    @property
    def instructions(self):  # type: () -> list[Instruction]
        """Get a list of instructions in this basic block."""
        result = []
        instruction = getInstructionAt(resolve(self.start_address))
        while instruction and instruction.getAddress().getOffset() < self.end_address:
            result.append(Instruction(instruction))
            instruction = instruction.getNext()
        return result

    @property
    def pcode(self):  # type: () -> list[PcodeOp]
        """Get a list of Pcode operations that this basic block was parsed to"""
        result = []
        for instruction in self.instructions:
            result.extend(instruction.pcode)
        return result

    @property
    def destinations(self):  # type: () -> list[BasicBlock]
        """Get a list of basic blocks that this basic block jumps to"""
        raw_refs = collect_iterator(self.raw.getDestinations(TaskMonitor.DUMMY))
        return [BasicBlock(raw.getDestinationBlock()) for raw in raw_refs]

    @property
    def sources(self):  # type: () -> list[BasicBlock]
        """Get a list of basic blocks that jump to this basic block"""
        raw_refs = collect_iterator(self.raw.getSources(TaskMonitor.DUMMY))
        return [BasicBlock(raw.getSourceBlock()) for raw in raw_refs]


class Variable(GhidraWrapper):
    @property
    def name(self):  # type: () -> str
        return self.raw.getName()

    @property
    def data_type(self):  # type: () -> DataType
        return DataType(self.raw.getDataType())

    @property
    def is_valid(self):  # type: () -> bool
        return self.raw.isValid()

    @property
    def comment(self):  # type: () -> str
        return self.raw.getComment()

    def set_comment(self, comment):  # type: (str) -> None
        self.raw.setComment(comment)

    @property
    def is_stack(self):  # type: () -> bool
        return self.raw.isStackVariable()

    @property
    def is_memory(self):  # type: () -> bool
        return self.raw.isMemoryVariable()

    @property
    def is_unique(self):  # type: () -> bool
        return self.raw.isUniqueVariable()

    @property
    def is_compound(self):  # type: () -> bool
        return self.raw.isCompoundVariable()

    @property
    def symbol(self):  # type: () -> Symbol
        return Symbol(self.raw.getSymbol())


class Parameter(Variable):
    @property
    def ordinal(self):  # type: () -> int
        return self.raw.getOrdinal()

    @property
    def formal_data_type(self):  # type: () -> DataType
        return DataType(self.raw.getFormalDataType())


class FunctionCall:
    def __init__(self, function, address):  # type: (Function, Addr) -> None
        self.function = function
        self.address = resolve(address)

    def get_high_pcode(self):  # type: () -> PcodeOp
        for pcode_op in PcodeOp.get_high_pcode_at(self.address):
            if pcode_op.opcode != pcode_op.CALL:
                continue
            return pcode_op

        raise RuntimeError("No CALL at {}".format(hex(self.address)))

    def get_varnodes(self):  # type: () -> dict[Varnode, int]
        basicblock = BasicBlock(self.address)
        emu = Emulator()
        return emu.propagate_varnodes(basicblock.start_address, self.address)

    def emulate(self):  # type: () -> Emulator
        basicblock = BasicBlock(self.address)
        emu = Emulator()
        emu.emulate(basicblock.start_address, self.address)
        return emu

    def get_args_as_varnodes(self):  # type: () -> list[Varnode]
        pcode_op = self.get_high_pcode()
        return pcode_op.inputs[1:]  # skip function addr

    def get_args(self, emulate=True):  # type: (bool) -> list[int]
        basicblock = BasicBlock(self.address)

        state = {}
        if emulate:
            # Almost no reason not to emulate - it takes some time, but it's
            # nothing compared to generating high pcode (required for getting args).
            emu = Emulator()
            state = emu.propagate_varnodes(basicblock.start_address, self.address)

        args = []
        for varnode in self.get_args_as_varnodes():
            varnode = varnode.free
            if varnode.has_value:
                args.append(varnode.value)
            elif varnode in state:
                args.append(state[varnode])
            else:
                args.append(None)
        return args


class Function(GhidraWrapper):
    @staticmethod
    def get(addr):  # type: (Addr|JavaObject) -> Function|None
        raw = currentProgram.getListing().getFunctionContaining(resolve(addr))
        if raw is None:
            return None
        return Function(raw)  # type: ignore

    @staticmethod
    def all():  # type: () -> list[Function]
        raw_functions = currentProgram.getFunctionManager().getFunctions(True)
        return [Function(f) for f in raw_functions]

    @staticmethod
    def create(address, name):  # type: (Addr, str) -> Function
        func = createFunction(resolve(address), name)
        return Function(func)

    @property
    def return_type(self):  # type: () -> DataType
        return DataType(self.raw.getReturnType())

    @property
    def return_variable(self):  # type: () -> Parameter
        return Parameter(self.raw.getReturn())

    @property
    def entrypoint(self):  # type: () -> int
        return self.raw.getEntryPoint().getOffset()

    @property
    def address(self):  # type: () -> int
        return self.entrypoint

    @property
    def name(self):  # type: () -> str
        return self.raw.getName()

    @property
    def comment(self):  # type: () -> str
        return self.raw.getComment()

    def set_comment(self, comment):  # type: (str) -> None
        self.raw.setComment(comment)

    @property
    def is_thunk(self):  # type: () -> bool
        return self.raw.isThunk()

    @property
    def is_external(self):  # type: () -> bool
        return self.raw.isExternal()

    @property
    def repeatable_comment(self):  # type: () -> str
        return self.raw.getRepeatableComment()

    def set_repeatable_comment(self, comment):  # type: (str) -> None
        self.raw.setRepeatableComment(comment)

    @property
    def parameters(self):  # type: () -> list[Parameter]
        return [Parameter(raw) for raw in self.raw.getParameters()]

    @property
    def local_variables(self):  # type: () -> list[Variable]
        return [Variable(raw) for raw in self.raw.getLocalVariables()]

    @property
    def variables(self):  # type: () -> list[Variable]
        return [Variable(raw) for raw in self.raw.getAllVariables()]

    def rename(self, name):  # type: (str) -> None
        self.raw.setName(name, SourceType.USER_DEFINED)

    @property
    def instructions(self):  # type: () -> list[Instruction]
        listing = currentProgram.getListing()
        raw_instructions = listing.getInstructions(self.raw.getBody(), True)
        return [Instruction(raw) for raw in raw_instructions]

    @property
    def xrefs(self):  # type: () -> list[Reference]
        raw_refs = getReferencesTo(resolve(self.entrypoint))
        return [Reference(raw) for raw in raw_refs]

    @property
    def xref_addrs(self):  # type: () -> list[int]
        return [xref.from_address for xref in self.xrefs]

    @property
    def callers(self):  # type: () -> list[Function]
        return [
            Function(raw) for raw in self.raw.getCallingFunctions(TaskMonitor.DUMMY)
        ]

    @property
    def called(self):  # type: () -> list[Function]
        return [Function(raw) for raw in self.raw.getCalledFunctions(TaskMonitor.DUMMY)]

    @property
    def fixup(self):  # type: () -> str
        return self.raw.getFixup()

    @fixup.setter
    def fixup(self, fixup):  # type: (str) -> None
        self.raw.setFixup(fixup)

    @property
    def calls(self):  # type: () -> list[FunctionCall]
        calls = []
        for ref in self.xrefs:
            if ref.is_call:
                calls.append(FunctionCall(self, ref.from_address))
        return calls

    @property
    def basicblocks(self):  # type: () -> list[BasicBlock]
        block_model = BasicBlockModel(currentProgram)
        blocks = block_model.getCodeBlocksContaining(
            self.raw.getBody(), TaskMonitor.DUMMY
        )
        return [BasicBlock(block) for block in blocks]

    def _decompile(self, simplify="decompile"):  # type: (str) -> JavaObject
        decompiler = DecompInterface()
        decompiler.openProgram(currentProgram)
        decompiler.setSimplificationStyle(simplify)
        decompiled = decompiler.decompileFunction(self.raw, 5, TaskMonitor.DUMMY)
        decompiler.closeProgram()
        decompiler.dispose()
        if decompiled is None:
            raise RuntimeError("Failed to decompile function {}".format(self.name))
        return decompiled

    def decompile(self):  # type: () -> str
        decompiled = self._decompile()
        return decompiled.getDecompiledFunction().getC()

    def get_high_function(self, simplify="decompile"):  # type: (str) -> HighFunction
        decompiled = self._decompile(simplify)
        return HighFunction(decompiled.getHighFunction())

    def get_high_pcode(self, simplify="decompile"):  # type: (str) -> list[PcodeOp]
        return self.get_high_function(simplify).pcode

    @property
    def high_pcode(self):  # type: () -> list[PcodeOp]
        return self.get_high_pcode()

    def get_high_pcode_at(self, address):  # type: (Addr) -> list[PcodeOp]
        return self.get_high_function().get_pcode_at(address)


class Symbol(GhidraWrapper):
    @staticmethod
    def get(raw_or_name):  # type: (JavaObject|str|Addr) -> Symbol
        if isinstance(raw_or_name, str):
            symbol_iterator = currentProgram.getSymbolTable().getSymbols(raw_or_name)
            symbols = collect_iterator(symbol_iterator)
            if not symbols:
                raise RuntimeError("Symbol {} not found".format(raw_or_name))
            raw = symbols[0]
        elif can_resolve(raw_or_name):
            raw = currentProgram.getSymbolTable().getPrimarySymbol(resolve(raw_or_name))
        else:
            raw = raw_or_name
        return Symbol(raw)

    @staticmethod
    def all():  # type: () -> list[Symbol]
        symbol_iterator = currentProgram.getSymbolTable().getAllSymbols()
        symbols = collect_iterator(symbol_iterator)
        return [Symbol(s) for s in symbols]

    @staticmethod
    def create(address, name):  # type: (Addr, str) -> Symbol
        raw = createLabel(resolve(address), name, False, SourceType.USER_DEFINED)
        return Symbol(raw)

    @property
    def address(self):  # type: () -> int
        return self.raw.getAddress().getOffset()

    @property
    def name(self):  # type: () -> str
        return self.raw.getName()

    @property
    def name_with_namespace(self):  # type: () -> str
        return self.raw.getName(True)

    @property
    def xrefs(self):  # type: () -> list[Reference]
        return [Reference(raw) for raw in self.raw.getReferences()]

    @property
    def xref_addrs(self):  # type: () -> list[int]
        return [xref.from_address for xref in self.xrefs]

    def set_type(self, datatype):  # type: (DataType) -> None
        create_data(self.address, datatype)


class DataType(GhidraWrapper):
    @staticmethod
    def get(name):  # type: (str) -> DataType|None
        for datatype in DataType.all():
            if datatype.name == name:
                return DataType(datatype)
        return None

    @staticmethod
    def all(only_local=False):  # type: (bool) -> list[DataType]
        datatypes = list(currentProgram.getDataTypeManager().getAllDataTypes())
        if only_local:
            return datatypes
        managers = (
            state.getTool().getService(DataTypeManagerService).getDataTypeManagers()
        )
        for manager in managers:
            for datatype in manager.getAllDataTypes():
                datatypes.append(datatype)
        return datatypes

    @property
    def name(self):  # type: () -> str
        """Get a name of this data type"""
        return self.raw.getName()

    def get_name(self, value):  # type: (int) -> str
        """Get Enum name for a given value"""
        return self.raw.getName(value)

    @staticmethod
    def from_c(c_code, insert=True):  # type: (str, bool) -> DataType
        """Parse C structure definition and return the parsed DataType.

        If insert (true by default), add it to current program.
        Example of a valid c_code is `typedef void* HINTERNET;`
        """
        dtm = currentProgram.getDataTypeManager()
        parser = CParser(dtm)

        new_dt = parser.parse(c_code)

        if insert:
            transaction = dtm.startTransaction("Adding new data")
            dtm.addDataType(new_dt, None)
            dtm.endTransaction(transaction, True)

        return new_dt


class Emulator(GhidraWrapper):
    def __init__(self):  # type: () -> None
        raw = EmulatorHelper(currentProgram)
        GhidraWrapper.__init__(self, raw)

    @property
    def pc(self):  # type: () -> Addr
        return self.raw.getExecutionAddress()

    def set_pc(self, address):  # type: (Addr) -> None
        pc = self.raw.getPCRegister()
        self.raw.writeRegister(pc, address)

    def read_register(self, reg):  # type: (Reg) -> int
        return self.raw.readRegister(reg)

    def write_register(self, reg, value):  # type: (Reg, int) -> None
        self.raw.writeRegister(reg, value)

    def get_bytes(self, address, length):  # type: (Addr, int) -> str
        bytelist = self.raw.readMemory(address, length)
        return "".join(chr(x % 256) for x in bytelist)

    def read_memory(self, address, length):  # type: (Addr, int) -> str
        return self.get_bytes(address, length)

    def write_memory(self, address, value):  # type: (Addr, str) -> None
        self.raw.writeMemory(address, value)

    def emulate(self, start, end):  # type: (Addr, Addr) -> None
        self.set_pc(start)
        end = resolve(end)
        self.raw.setBreakpoint(end)
        is_breakpoint = self.raw.run(TaskMonitor.DUMMY)
        self.raw.clearBreakpoint(end)
        if not is_breakpoint:
            err = self.raw.getLastError()
            raise RuntimeError("Error when running: {}".format(err))

    def read_varnode(self, varnode):  # type: (Varnode) -> int
        if varnode.is_constant:
            return varnode.value
        elif varnode.is_address:
            rawnum = self.raw.readMemory(varnode.offset, varnode.size)
            return from_bytes(rawnum)
        elif varnode.is_unique:
            space = currentProgram.getAddressFactory().getUniqueSpace()
            offset = space.getAddress(varnode.offset)
            rawnum = self.raw.readMemory(offset, varnode.size)
            return from_bytes(rawnum)
        elif varnode.is_register:
            language = currentProgram.getLanguage()
            reg = language.getRegister(varnode.raw.getAddress(), varnode.size)
            return self.raw.readRegister(reg)
        raise RuntimeError("Unsupported varnode type")

    def trace_pcode(
        self, start, end, callback
    ):  # type: (Addr, Addr, Callable[[PcodeOp], None]) -> None
        self.set_pc(start)
        current = resolve(start)
        end = resolve(end)
        while current != end:
            success = self.raw.step(TaskMonitor.DUMMY)
            if not success:
                err = self.raw.getLastError()
                raise RuntimeError("Error at {}: {}".format(current, err))

            instruction = Instruction(current)
            for op in instruction.pcode:
                callback(op)

            current = self.raw.getExecutionAddress()

    def propagate_varnodes(
        self, start, end
    ):  # type: (Addr, Addr) -> dict[Varnode, int]
        known_state = {}  # type: dict[Varnode, int]

        def callback(op):  # type: (PcodeOp) -> None
            resolved = True
            for inp in op.inputs:
                if inp in known_state:
                    continue
                if inp.is_constant or inp.is_address:
                    continue
                resolved = False
                break

            if resolved and op.output is not None:
                res = self.read_varnode(op.output)
                known_state[op.output] = res

        self.trace_pcode(start, end, callback)
        return known_state


def xor(a, b):  # type: (str, str) -> str
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))


def create_data(address, datatype):  # type: (Addr, DataType) -> None
    try:
        createData(resolve(address), unwrap(datatype))
    except:
        clearListing(resolve(address))
        createData(resolve(address), unwrap(datatype))


def get_string(address):  # type: (Addr) -> str|None
    string = getDataAt(resolve(address))
    if string and string.hasStringValue():
        return string.getValue()
    return None


def current_location():  # type: () -> int
    return currentLocation.getAddress().getOffset()


def get_u32(address):
    return from_bytes(get_bytes(address, 2))


def get_bytes(address, length):  # type: (Addr, int) -> str
    address = resolve(address)
    return "".join(chr(x % 256) for x in getBytes(address, length))


def from_bytes(b):  # type: (str | list[int]) -> int
    if isinstance(b, str):
        b = [ord(x) for x in b]
    return sum((v % 256) << (i * 8) for i, v in enumerate(b))

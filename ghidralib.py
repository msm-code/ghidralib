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

from abc import abstractmethod
from ghidra.app.decompiler import (
    ClangSyntaxToken,
    ClangCommentToken,
    ClangBreak,
    ClangTokenGroup as GhClangTokenGroup,
    DecompInterface,
)
from ghidra.app.services import DataTypeManagerService, GraphDisplayBroker
from ghidra.app.util import PseudoDisassembler
from ghidra.app.util.cparser.C import CParser
from ghidra.app.emulator import EmulatorHelper
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.plugin.assembler import Assemblers
from ghidra.app.plugin.core.analysis import ConstantPropagationContextEvaluator
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.util import SearchConstants
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SourceType, RefType as GhRefType
from ghidra.program.model.pcode import (
    HighFunctionDBUtil,
    Varnode as GhVarnode,
    BlockGraph as GhBlockGraph,
    BlockCopy,
    HighFunction as GhHighFunction,
    JumpTable,
)
from ghidra.program.model.lang import Register as GhRegister
from ghidra.program.model.block import BasicBlockModel, SimpleBlockModel
from ghidra.program.model.address import (
    GenericAddress,
    AddressSet as GhAddressSet,
    AddressSpace,
)
from ghidra.program.model.listing import ParameterImpl, Function as GhFunction, Data as GhData
from ghidra.program.util import SymbolicPropogator as GhSymbolicPropogator
from ghidra.service.graph import GraphDisplayOptions, AttributedGraph, GraphType
from java.awt import Color
from java.util import ArrayList
from java.math import BigInteger
import sys


__version__ = "0.2.0"


try:
    # Import types for static type hints (and catch import error in Jython)
    from typing import Any, Callable, TYPE_CHECKING, Iterator, TypeVar, Generic
except ImportError:
    TYPE_CHECKING = False


if sys.version_info.major == 2:
    # Jython support: this section is Jython specific
    from __main__ import (
        toAddr,
        createFunction,
        getDataAt,
        createLabel,
        getMonitor,
        createData,
        clearListing,
        getReferencesTo,
        getInstructionAt,
        getBytes,
        getState,
        getMonitor,
        removeSymbol,
        getCurrentProgram,
        disassemble,
        analyzeChanges,
        setBytes,
    )

    # Python2 specific type definitions
    # The goal is to support both languages with a single codebase

    if not TYPE_CHECKING:
        bytes = str  # there is no "bytes" in python3.

    from array import array

    def _is_array(value):  # type: (object) -> bool
        """Return True if the given value is a Java array"""
        return isinstance(value, array)

    def _bytes_as_list(value):  # type: (bytes) -> list[int]
        """Convert the given string to a list of bytes."""
        return [ord(c) for c in value]  # type: ignore

    def _bytes_from_bytelist(bytelist):  # type: (object) -> bytes
        """Convert the given Java array of bytes to python bytes"""
        return "".join(chr(x % 256) for x in bytelist)  # type: ignore

    def _asbytes(value):  # type: (str) -> bytes
        """Convert the given string to bytes. No-op in py2"""
        return value  # type: ignore

    def _unhex(s):  # type: (str) -> bytes
        """Decode hexadecimal string to bytes. Internal helper."""
        return s.replace(" ", "").replace("\n", "").decode("hex")  # type: ignore

    def _enhex(s):  # type: (bytes) -> str
        """Encode bytes to hexadecimal string. Internal helper."""
        return s.encode("hex")  # type: ignore

else:
    # PyGhidra support: this section is PyGhidra specific
    from pyghidra.script import get_current_interpreter

    interpreter = get_current_interpreter()
    toAddr = get_current_interpreter().toAddr
    createFunction = get_current_interpreter().createFunction
    getDataAt = get_current_interpreter().getDataAt
    createLabel = get_current_interpreter().createLabel
    getState = get_current_interpreter().getState
    createData = get_current_interpreter().createData
    clearListing = get_current_interpreter().clearListing
    getReferencesTo = get_current_interpreter().getReferencesTo
    getInstructionAt = get_current_interpreter().getInstructionAt
    getBytes = get_current_interpreter().getBytes
    getMonitor = get_current_interpreter().getMonitor
    removeSymbol = get_current_interpreter().removeSymbol
    getCurrentProgram = get_current_interpreter().getCurrentProgram
    disassemble = get_current_interpreter().disassemble
    analyzeChanges = get_current_interpreter().analyzeChanges
    setBytes = get_current_interpreter().setBytes

    # Python3 specific type definitions
    # The goal is to support both languages with a single codebase

    long = int  # There is no "long" in Python3

    class unicode:
        """A fake stub class, to keep type-checker relatively happy"""

        def encode(self):  # type: () -> str
            """A fake method, to keep type-checker relatively happy"""
            raise NotImplementedError("This method should never be called")

    from jpype import JArray

    def _is_array(value):  # type: (object) -> bool
        """Return True if the given value is a Java array"""
        return isinstance(value, JArray)

    def _bytes_as_list(value):  # type: (bytes) -> list[int]
        """Convert the given string to a list of bytes (no-op in py3)"""
        return value  # type: ignore

    def _bytes_from_bytelist(bytelist):  # type: (object) -> bytes
        """Convert the given Java array of bytes to python bytes"""
        return bytes(bytelist)  # type: ignore

    def _asbytes(value):  # type: (str) -> bytes
        """Convert the given string to bytes.

        Ugly hack in python3 - This converts chr(N) to byte N for every N."""
        return value.encode("latin1")

    def _unhex(s):  # type: (str) -> bytes
        """Decode hexadecimal string to bytes. Internal helper."""
        return bytes.fromhex(s)

    def _enhex(s):  # type: (bytes) -> str
        """Encode bytes to hexadecimal string. Internal helper."""
        return s.hex()


# Early Python2.x aliases
if TYPE_CHECKING:
    # Python 2.x archaism.
    long = int
    unicode = str  # type: ignore


class JavaObject:
    """A fake class, used for static type hints."""

    def __getattribute__(self, name):  # type: (str) -> Any
        """This attribute exists to make mypy happy."""
        pass


def _python_int(value):
    """Convert a given int-like value to a Python integer.

    This is a jpype helper: it converts Java BigIntegers to Python ints.

    :param value: The value to convert, either a Python int or BigInteger.
    :return: The converted value, always a python int."""
    if isinstance(value, BigInteger):
        return int(value.toString())  # wtf
    return value


def _python_str(string):  # type: (str|unicode) -> str
    """Convert a given string-like value to a Python `str`.

    In particular, this will convert unicode objects to normal strings.
    This method only matters for Jython (Python 2) compatibility"""
    if isinstance(string, unicode):
        # This can only happen for
        return string.encode()
    return string


class GhidraWrapper(object):
    """The base class for all Ghidra wrappers.

    This function tries to be as transparent as possible - for example, it will
    not raise an error on double-wrapping, or when passed instead of a
    Java type.

        >>> instr = getInstructionAt(getAddr(0x1234))
        >>> GhidraWrapper(instr)
        <Instruction 0x1234>
        >>> GhidraWrapper(GhidraWrapper(instr))
        <Instruction 0x1234>
        >>> getInstructionBefore(Instruction(instr))
        <Instruction 0x1233>

    Similarly, equality is based on the underlying Java object."""

    def __init__(self, raw):  # type: (JavaObject|int|str|GhidraWrapper) -> None
        """Initialize the wrapper.

        This function will try to resolve the given object to a Ghidra object.
        The algorithm is as follows:

        * If "raw" is a primitive type (int, long, str, unicode, Address),
          try to resolve it with a static "get" method of the subclass.
        * If "raw" is a GhidraWrapper, unwrap it (so GhidraWrapper(GhidraWrapper(x))
          is always the same as GhidraWrapper(x).
        * If "raw" is None at this point, raise an exception.
        * If the subclass has attribute UNDERLYING_CLASS, assert that the wrapped
          type is of the expected type.
        * Save the final "raw" value."""

        if isinstance(raw, (int, long, str, unicode, GenericAddress)):
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

        # TODO - remove the conditional checks and implement this everywhere
        if hasattr(self, "UNDERLYING_CLASS"):
            wrapped_type = getattr(self, "UNDERLYING_CLASS")
            if not isinstance(raw, wrapped_type):
                raise RuntimeError(
                    "You are trying to wrap {} as {}".format(
                        raw.__class__.__name__, self.__class__.__name__
                    )
                )

        def _java_cast(raw):  # type: (Any) -> JavaObject
            """This function exists only to make type-checker happy"""
            return raw

        self.raw = _java_cast(raw)

    def __str__(self):  # type: () -> str
        """Return a string representation of this object.

        This just forwards the call to the underlying object."""
        return self.raw.__str__()

    def __repr__(self):  # type: () -> str
        """Return a string representation of this object.

        This just forwards the call to the underlying object."""
        return self.raw.__repr__()

    def __tojava__(self, klass):
        """Make it possible to pass this object to Java methods.

        This only works in Jython, I didn't find a way to do this in JPype yet."""
        return self.raw

    def __hash__(self):  # type: () -> int
        """Return the hash of this object.

        This just forwards the call to the underlying object."""
        return self.raw.hashCode()

    def __eq__(self, other):  # type: (object) -> bool
        """Check if this object is equal to another.

        This just forwards the call to the underlying object."""
        if isinstance(other, GhidraWrapper):
            return self.raw.equals(other.raw)
        return self.raw.equals(other)


# Aliases just for typechecking.
if TYPE_CHECKING:
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

    DataT = GhidraWrapper | JavaObject | str
    # This library accepts one of two things as a DataType:
    # 1. A Ghidra DataType object
    # 2. A string representing a DataType name (will be resolved)


# For isinstance checks, so i can forget about this distinction once again
Str = (str, bytes, unicode)


# Use this color for highlight by default - it should work with any theme.
HIGHLIGHT_COLOR = SearchConstants.SEARCH_HIGHLIGHT_COLOR  # type: Color


def resolve(addr):  # type: (Addr) -> GenericAddress
    """Convert an arbitrary addressable value to a Ghidra Address object.

    This library accepts one of three things as addressses:

    1. A Ghidra Address object
    2. An integer representing an address
    3. A string representing a symbol name

    This function is responsible from converting the addressable values (`Addr`)
    to Ghidra addresses (`GenericAddress`).

        >>> resolve(0x1234)
        0x1234
        >>> resolve(Symbol("main"))
        0x1234
        >>> resolve(toAddr(0x1234))
        0x1234

    :param addr: An addressable value.
    :return: A GenericAddress object representing the passed address.

    """
    if isinstance(addr, unicode):  # Why, Ghidra?
        addr = addr.encode()
    if isinstance(addr, GenericAddress):
        return addr
    if isinstance(addr, (int, long)):
        # Why convert to string? Java cannot handle large (unsigned) integers :/
        return toAddr("{:x}".format(addr))
    if isinstance(addr, str):
        return toAddr(Symbol(addr).address)
    raise TypeError("Address must be a ghidra Address, int, or str")


def try_resolve(addr):  # type: (Addr) -> GenericAddress | None
    """Convert an arbitrary addressable value to a Ghidra Address object.

    See `resolve` documentation for more details.

    :param addr: An addressable value.
    :return: A GenericAddress representing the value, or None resolving failed."""
    try:
        return resolve(addr)
    except:
        return None


def can_resolve(addr):  # type: (Addr) -> bool
    """Check if a passed value address can be resolved.

    This is useful for checking if `resolve()` will succeed.
    See `resolve` documentation for more details."""
    return isinstance(addr, (GenericAddress, int, long, unicode, str))


def unwrap(wrapper_or_java_type):  # type: (JavaObject|GhidraWrapper) -> JavaObject
    "If the argument is a GhidraWrapper, return the underlying Java object." ""
    if isinstance(wrapper_or_java_type, GhidraWrapper):
        return wrapper_or_java_type.raw
    return wrapper_or_java_type


def collect_iterator(iterator):  # type: (JavaObject) -> list
    """Collect a Java iterator to a Python list."""
    result = []
    while iterator.hasNext():
        result.append(iterator.next())
    return result


if TYPE_CHECKING:
    # Hacky workaround to have a optional generic type variable using comment syntax.
    T = TypeVar("T")
    GenericT = Generic[T]
else:

    class GenericT:
        pass


class Graph(GenericT, GhidraWrapper):
    """Wraps a Ghidra AttributedGraph object.

    We'd like to store arbitrary object in the graph, but it only supports
    strings for keys (and names). We have a way to convert objects we are
    interested in to strings - see _get_unique_string() method."""

    # TODO: maybe this should be a GDirectedGraph, so we get some algorithms
    # for free, and we can just convert it for display.

    def __init__(self, raw):  # type: (AttributedGraph) -> None
        """Create a new Graph wrapper.

        We have to keep track of additional data, since AttributedGraph is a bit
        clunky and can only store string IDs and string values.

        :param raw: The AttributedGraph object to wrap."""
        GhidraWrapper.__init__(self, raw)
        self.data = {}

    @staticmethod
    def create(name=None, description=None):  # type: (str|None, str|None) -> Graph[Any]
        """Create a new Graph.

        :param name: The name of the graph. If None, a default name will be used.
        :param description: The description of the graph. If
        None, a default description will be used.
        :returns: a new Graph object.
        """
        name = name or "Graph"
        description = description or "Graph"
        graphtype = GraphType(name, description, ArrayList([]), ArrayList([]))
        return Graph(AttributedGraph(name, graphtype, description))

    @staticmethod
    def construct(
        vertexlist, getedges
    ):  # type: (list[T], Callable[[T], list[T]]) -> Graph[T]
        """Create a new Graph from a list of vertices and a function to get edges.

        :param vertexlist: The list of vertices.
        :param getedges: A function that gets a list of destinations from a vertex."""
        g = Graph.create()
        for v in vertexlist:
            g.vertex(v)
        for v in vertexlist:
            for dest in getedges(v):
                if dest in g:
                    g.edge(v, dest)
        return g

    def __contains__(self, vtx):  # type: (T) -> bool
        """Check if a given vertex exists in this graph.

        :param vtx: The ID of the vertex to check."""
        vid = _get_unique_string(vtx)
        vobj = self.raw.getVertex(vid)
        return self.raw.containsVertex(vobj)

    def has_vertex(self, vtx):  # type: (T) -> bool
        """Check if a given vertex exists in this graph.

        :param vtx: The ID of the vertex to check."""
        return vtx in self

    def vertex(self, vtx, name=None):  # type: (T, str|None) -> T
        """Get or create a vertex in this graph.

        :param vtx: The ID of the new vertex, or any "Vertexable" object
        that can be used to identify the vertex.
        :param name: The name of the vertex. If not provided,
        the ID will be used as the name.
        :returns: vtx parameter is returned"""
        vid = _get_unique_string(vtx)
        name = name or str(vtx)
        self.raw.addVertex(vid, name)
        self.data[vid] = vtx
        return vtx

    def edge(self, src, dst):  # type: (T, T) -> None
        """Create an edge between two vertices in this graph.

        :param src: The source vertex ID.
        :param dst: The destination vertex ID."""
        srcid = _get_unique_string(src)
        dstid = _get_unique_string(dst)
        srcobj = self.raw.getVertex(srcid)
        dstobj = self.raw.getVertex(dstid)
        self.raw.addEdge(srcobj, dstobj)

    @property
    def vertices(self):  # type: () -> list[T]
        """Get all vertices in this graph.

        Warning: this constructs the list every time, so it's not a light operation.
        Use vertex_count for counting."""
        return [self.__resolve(vid.getId()) for vid in self.raw.vertexSet()]

    @property
    def vertex_count(self):  # type: () -> int
        """Return the number of vertices in this graph."""
        return self.raw.vertexSet().size()

    def __len__(self):  # type: () -> int
        """Return the number of vertices in this graph.

        To get the number of edges, use edge_count."""
        return self.vertex_count

    @property
    def edges(self):  # type: () -> list[tuple[T, T]]
        """Get all edges in this graph.

        Warning: this constructs the list every time, so it's not a light operation.
        Use edge_count for counting."""
        result = []
        for e in self.raw.edgeSet():
            frm = self.raw.getEdgeSource(e)
            to = self.raw.getEdgeTarget(e)
            frmobj = self.data.get(frm, frm)
            toobj = self.data.get(to, to)
            result.append((frmobj, toobj))
        return result

    @property
    def edge_count(self):  # type: () -> int
        """Return the number of edges in this graph."""
        return self.raw.edgeSet().size()

    @property
    def name(self):  # type: () -> str
        """Return the name of this graph."""
        return self.raw.getName()

    @property
    def description(self):  # type: () -> str
        """Return the description of this graph."""
        return self.raw.getDescription()

    def to_dot(self):  # type: () -> str
        """Return a DOT representation of this graph."""
        result = []
        result.append("digraph {} {{".format(self.name))
        for v in self.raw.vertexSet():
            result.append('    "{}" [label="{}"];'.format(v.getId(), v.getName()))
        for e in self.raw.edgeSet():
            frm = self.raw.getEdgeSource(e)
            to = self.raw.getEdgeTarget(e)
            result.append('    "{}" -> "{}";'.format(frm.getId(), to.getId()))
        result.append("}")
        return "\n".join(result)

    def show(self):  # type: () -> None
        """Display this graph in the Ghidra GUI."""
        graphtype = self.raw.getGraphType()
        description = graphtype.getDescription()
        options = GraphDisplayOptions(graphtype)

        broker = getState().tool.getService(GraphDisplayBroker)
        display = broker.getDefaultGraphDisplay(False, getMonitor())
        display.setGraph(self.raw, options, description, False, getMonitor())

    def __resolve(self, vid):  # type: (str) -> T
        """Resolve a vertex ID to a vertex object.

        :param vid: The ID of the vertex to resolve."""
        if vid in self.data:
            return self.data[vid]
        else:
            return vid  # type: ignore graph created outside of ghidralib?

    def dfs(
        self, origin, callback=lambda _: None
    ):  # type: (T, Callable[[T], None]) -> dict[T, T|None]
        """Perform a depth-first search on this graph, starting from the given vertex.

        The callback will be called for each vertex visited when first visited, and
        the returned value is a dictionary of parent vertices for each visited vertex.

            >>> g = Graph.create()
            >>> a, b, c = g.vertex("a"), g.vertex("b"), g.vertex("c")
            >>> g.edge(a, b)
            >>> g.edge(b, c)
            >>> g.dfs(a)
            {'a': None, 'b': 'a', 'c': 'b'}

        Warning: This won't reach every node in the graph, if it's not connected.

        :param origin: The ID of the vertex to start the search from.
        :param callback: A callback function to call for each vertex visited.
        :returns: A dictionary of parent vertices for each visited vertex.
        """
        tovisit = [(None, _get_unique_string(origin))]
        visited = set()
        parents = {origin: None}  # type: dict[T, T|None]
        while tovisit:
            parent, vid = tovisit.pop()
            if vid in visited:
                continue
            visited.add(vid)
            vobj = self.__resolve(vid)
            parents[vobj] = parent
            callback(vobj)
            for edge in self.raw.edgesOf(self.raw.getVertex(vid)):
                tovisit.append((vobj, self.raw.getEdgeTarget(edge).getId()))
        return parents

    def toposort(self, origin):  # type: (T) -> list[T]
        """Perform a topological sort on this graph, starting from the given vertex.
        :param origin: The ID of the vertex to start the sort from.

        The order is such that if there is an edge from A to B, then A will come
        before B in the list. This means that if the graph is connected and acyclic
        then "origin" will be the last element in the list.

        On a practical example, for a call graph, this means that if A calls B, then
        B will be before A in the list - so if you want to process from the bottom up,
        you should use the entry point of the program as the origin. In the example
        below, the entry point is "a", "a" calls "b", and "b" calls "c":

            >>> g = Graph.create()
            >>> a, b, c = g.vertex("a"), g.vertex("b"), g.vertex("c")
            >>> g.edge(a, b)
            >>> g.edge(b, c)
            >>> g.toposort(a)
            ['c', 'b', 'a']

        :param origin: The ID of the origin vertex to start the sort from.
        :returns: a list of vertex IDs in topological order."""
        visited = set()
        result = []

        def dfs(vid):
            visited.add(vid)
            for edge in self.raw.edgesOf(self.raw.getVertex(vid)):
                target = self.raw.getEdgeTarget(edge)
                if target.getId() not in visited:
                    dfs(target.getId())
            result.append(self.__resolve(vid))

        dfs(_get_unique_string(origin))
        for vid in self.raw.vertexSet():
            if vid.getId() not in visited:
                dfs(vid.getId())
        return result

    def bfs(
        self, origin, callback=lambda _: None
    ):  # type: (T, Callable[[T], None]) -> dict[T, T|None]
        """Perform a breadth-first search on this graph, starting from the given vertex.

        The callback will be called for each vertex visited when first visited, and
        the returned value is a dictionary of parent vertices for each visited vertex.

            >>> g = Graph.create()
            >>> a, b, c = g.vertex("a"), g.vertex("b"), g.vertex("c")
            >>> g.edge(a, b)
            >>> g.edge(b, c)
            >>> g.bfs(a)
            {'a': None, 'b': 'a', 'c': 'b'}

        Warning: This won't reach every node in the graph, if it's not connected.

        :param origin: The ID of the vertex to start the search from.
        :param callback: A callback function to call for each vertex visited.
        """
        tovisit = [(None, _get_unique_string(origin))]
        visited = set()
        parents = {origin: None}  # type: dict[T, T|None]
        while tovisit:
            parent, vid = tovisit.pop(0)
            if vid in visited:
                continue
            visited.add(vid)
            vobj = self.__resolve(vid)
            parents[vobj] = parent
            callback(vobj)
            for edge in self.raw.edgesOf(self.raw.getVertex(vid)):
                tovisit.append((vobj, self.raw.getEdgeTarget(edge).getId()))
        return parents


class BodyTrait:
    """A trait for objects that have a body.

    It provides generic methods that work with anything that has a body
    (an assigned set of addresses in the program), such as highlighting."""

    @property
    @abstractmethod
    def body(self):  # type: () -> AddressSet
        """The body of this object"""

    def highlight(self, color=HIGHLIGHT_COLOR):  # type: (Color) -> None
        """Highlight this instruction in the listing."""
        self.body.highlight(color)

    def unhighlight(self):  # type: () -> None
        """Clear the highlight from this instruction."""
        self.body.unhighlight()


class HighVariable(GhidraWrapper):
    @property
    def symbol(self):  # type: () -> HighSymbol
        return HighSymbol(self.raw.getSymbol())

    def rename(self, new_name):  # type: (str) -> None
        """Rename this high variable."""
        self.symbol.rename(new_name)

    @property
    def size(self):  # type: () -> int
        """Return the size of this variable in bytes"""
        return self.raw.getSize()

    @property
    def data_type(self):  # type: () -> DataType
        """Return the data type of this variable"""
        return DataType(self.raw.getDataType())

    @property
    def name(self):  # type: () -> str
        """Return the name of this variable"""
        return self.raw.getName()

    @property
    def varnode(self):  # type: () -> Varnode
        """Return the Varnode that represents this variable"""
        return Varnode(self.raw.getRepresentative())

    @property
    def varnodes(self):  # type: () -> list[Varnode]
        """Return all Varnodes that represent this variable at some point"""
        return [Varnode(vn) for vn in self.raw.getInstances()]

    @property
    def is_unaffected(self):  # type: () -> bool
        """Return True if ALL varnodes of this variable are is unaffected."""
        return any(vn.is_unaffected for vn in self.varnodes)

    @property
    def is_persistent(self):  # type: () -> bool
        """Return True if ALL varnodes of this variable are persistent."""
        return any(vn.is_persistent for vn in self.varnodes)

    @property
    def is_addr_tied(self):  # type: () -> bool
        """Return True if ALL varnodes of this variable are addr tied."""
        return any(vn.is_addr_tied for vn in self.varnodes)

    @property
    def is_input(self):  # type: () -> bool
        """Return True if ALL varnodes of this variable are input."""
        return any(vn.is_input for vn in self.varnodes)

    @property
    def is_free(self):  # type: () -> bool
        """Return True if ALL varnodes of this variable are free."""
        return all(vn.is_free for vn in self.varnodes)


class HighSymbol(GhidraWrapper):
    def rename(
        self, new_name, source=SourceType.USER_DEFINED
    ):  # type: (str, SourceType) -> None
        """Rename this high symbol.

        :param new_name: The new name of the symbol
        :param source: The source of the symbol"""
        HighFunctionDBUtil.updateDBVariable(self.raw, new_name, None, source)

    @property
    def size(self):  # type: () -> int
        """Return the size of this symbol in bytes"""
        return self.raw.getSize()

    @property
    def data_type(self):  # type: () -> DataType
        """Return the data type of this symbol"""
        return DataType(self.raw.getDataType())

    @property
    def variable(self):  # type: () -> HighVariable|None
        """Return the high variable associated with this symbol, if any.

        The symbol may have multiple HighVariables associated with it.
        This method returns the biggest one."""
        raw = self.raw.getHighVariable()
        if raw is None:
            return None
        return HighVariable(raw)

    @property
    def name(self):  # type: () -> str
        """Return the name of this symbol"""
        return self.raw.getName()

    @property
    def symbol(self):  # type: () -> Symbol|None
        """Get the corresponding symbol, if it exists."""
        raw = self.raw.getSymbol()
        if raw is None:
            return None
        return Symbol(raw)

    @property
    def is_this_pointer(self):  # type: () -> bool
        """Return True if this symbol is a "this" pointer for a class"""
        return self.raw.isThisPointer()


class Register(GhidraWrapper):
    @staticmethod
    def get(raw_or_name):  # type: (str|JavaObject) -> Register|None
        """Get a register by name"""
        if isinstance(raw_or_name, Str):
            raw_or_name = Program.current().getLanguage().getRegister(raw_or_name)
            if raw_or_name is None:
                return None
        return Register(raw_or_name)

    @property
    def name(self):  # type: () -> str
        """Return the name of this register"""
        return self.raw.getName()

    @property
    def size(self):  # type: () -> int
        """Return the size of this register in bytes

        This will tell the total number of bytes this register contains -
        because register values don't have to be byte-aligned"""
        return self.raw.getNumBytes()

    @property
    def varnode(self):  # type: () -> Varnode
        """Return the varnode associated with this register

        Warning: this doesn't support registers that are not byte-aligned
        (for example, flag registers). It will round the address down to byte.
        """
        raw = GhVarnode(self.raw.getAddress(), self.raw.getNumBytes())
        return Varnode(raw)


class Varnode(GhidraWrapper):
    @property
    def has_value(self):  # type: () -> bool
        """Return true if this varnode can be converted to a integer value.

        In particular, this will return true for Address and Constant varnodes"""
        return self.value is not None

    @property
    def value(self):  # type: () -> int|None
        """Get the value of this varnode. Traverse defining pcodeops if necessary."""
        if self.is_address or self.is_constant:
            return self.offset
        if self.defining_pcodeop is None:
            return None
        return self.defining_pcodeop.result

    @property
    def offset(self):  # type: () -> int
        return int(self.raw.getOffset())

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
        """Return True if this varnode is stored entirely in a register.

        Warning: this does not mean that it can be cast to a register! This may
        be, for example, upper 32 bits of RAX. Use is_named_register instead."""
        return self.raw.isRegister()

    @property
    def is_named_register(self):  # type: () -> bool
        """ "Return True if this varnode is stored entirely in a named register.

        "Named" in this context means that it has a conventional name, like RAX.
        Not all register varnodes are named, for example, the upper 32 bits of RAX
        have no commonly used name."""
        language = Program.current().getLanguage()
        raw = language.getRegister(self.raw.getAddress(), self.size)
        return raw is not None

    @property
    def as_register(self):  # type: () -> str
        """Return the name of the register this varnode is stored in.

        Warning: even if is_register returns true, this does not mean you can use
        this method safely. Use is_named_register to make sure."""
        language = Program.current().getLanguage()
        raw = language.getRegister(self.raw.getAddress(), self.size)
        return raw.getName()

    @property
    def is_address(self):  # type: () -> bool
        return self.raw.isAddress()

    @property
    def is_unique(self):  # type: () -> bool
        return self.raw.isUnique()

    @property
    def is_hash(self):  # type: () -> bool
        return self.raw.isHash()

    @property
    def is_stack(self):  # type: () -> bool
        spaceid = self.raw.getSpace()
        spacetype = AddressSpace.ID_TYPE_MASK & spaceid
        return spacetype == AddressSpace.TYPE_STACK

    def rename(self, new_name):  # type: (str) -> None
        """Try to rename the current varnode. This only makes sense for variables."""
        self.symbol.rename(new_name)

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
        value = self.value
        if value is not None:
            return value
        elif self.is_register:
            if self.is_named_register:
                return self.as_register
            return "reg:{:x}:{:x}".format(self.offset, self.size)
        elif self.is_unique:
            return "uniq:{:x}:{:x}".format(self.offset, self.size)
        elif self.is_hash:
            return "hash:{:x}:{:x}".format(self.offset, self.size)
        elif self.is_stack:
            return "stack:{:x}:{:x}".format(self.offset, self.size)
        raise RuntimeError("Unknown varnode type")

    @property
    def is_unaffected(self):  # type: () -> bool
        return self.raw.isUnaffected()

    @property
    def is_persistent(self):  # type: () -> bool
        return self.raw.isPersistent()

    @property
    def is_addr_tied(self):  # type: () -> bool
        return self.raw.isAddrTied()

    @property
    def is_input(self):  # type: () -> bool
        return self.raw.isInput()

    @property
    def is_free(self):  # type: () -> bool
        return self.raw.isFree()

    @property
    def defining_pcodeop(self):  # type: () -> PcodeOp|None
        """Return a PcodeOp that defined this varnode"""
        raw = self.raw.getDef()
        if raw is None:
            return None
        return PcodeOp(raw)

    @property
    def descendants(self):  # type: () -> list[PcodeOp]
        """Return a list of all descendants of this varnode"""
        if self.raw.getDescendants() is None:
            return []
        return [PcodeOp(x) for x in self.raw.getDescendants()]

    def intersects(self, other):  # type: (Varnode) -> list[PcodeOp]
        """Return true if this varnode intersects other"""
        return self.raw.intersects(other.raw)


class PcodeOp(GhidraWrapper):
    """Pcode is a Ghidra's low-level intermediate language.
    Instructions from any processor are transformed into PCode
    before any analysis takes place. There is a finite number of
    possible operations.

    While Ghidra doesn't define "High Pcode", this library refers
    to analysed Pcode as "High Pcode". While theoretically still
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

    @property
    def result(self):  # type: () -> int|None
        """Try to evaluate the pcode operation to a constant value.

        Right now this is very poor and doesn't try to implement most of the opcodes.
        Mostly because I suspect I'm reinventing the wheel, and there is code to do
        this already in Ghidra.

        :return: Result of this operation, or None if can't be evaluated as const."""
        if self.opcode == PcodeOp.COPY:
            return self.inputs[0].value
        return None


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
    def has_children(self):  # type: () -> bool
        """Returns True if this block has any children and can be iterated over.

        This function is necessary because Ghidra's code uses isinstance()
        checks to dispatch types. We return true for instances of Java BlockGraph."""
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
    @staticmethod
    def get(address):  # type: (JavaObject|str|Addr) -> HighFunction|None
        """Get a HighFunction at a given address, or None if there is none."""
        if isinstance(address, GhHighFunction):
            return HighFunction(address)
        func = Function.get(address)
        if func is None:
            return None
        return func.high_function

    @property
    def function(self):  # type: () -> Function
        """Get the underlying function of this high function."""
        return Function(self.raw.getFunction())

    def get_pcode_at(self, address):  # type: (Addr) -> list[PcodeOp]
        """Get a list of PcodeOps at a given address.

        This list may be empty even if there are instructions at that address."""
        address = resolve(address)
        return [PcodeOp(raw) for raw in self.raw.getPcodeOps(address)]

    @property
    def pcode(self):  # type: () -> list[PcodeOp]
        """Get a list of all high PcodeOps in this function.

        Note: high PcodeOps are called PcodeOpAST internally."""
        return [PcodeOp(raw) for raw in self.raw.getPcodeOps()]

    @property
    def data_flow(self):  # type: () -> Graph[PcodeOp]
        """Get a data flow graph of varnodes in this function.

        Note: I don't think this method is currently very useful, but you can
        use it to easily get information about all varnodes that impact a value of
        another varnode

        :returns: A graph where vertexes are varnodes, and edges mean that
        target varnode is a result of operation on source varnodes."""
        g = Graph.create()
        for op in self.pcode:
            if op.output:
                for inp in op.inputs:
                    g.vertex(op.output)
                    g.vertex(inp)
                    g.edge(inp, op.output)
        return g

    @property
    def basicblocks(self):  # type: () -> list[PcodeBlock]
        """Get a list of basic blocks in this high function."""
        return [PcodeBlock(raw) for raw in self.raw.getBasicBlocks()]

    @property
    def pcode_tree(self):  # type: () -> BlockGraph
        """Get an AST-like representation of the function's Pcode.

        Warning: this method needs to decompile the function, and is therefore slow."""
        edge_map = {}
        ingraph = GhBlockGraph()
        for block in self.basicblocks:
            gb = BlockCopy(block.raw, block.raw.getStart())
            ingraph.addBlock(gb)
            edge_map[block.raw] = gb

        for block in self.basicblocks:
            for edge in block.outgoing_edges:
                ingraph.addEdge(edge_map[block.raw], edge_map[edge.raw])

        ingraph.setIndices()
        decompiler = DecompInterface()
        decompiler.openProgram(Program.current())
        outgraph = decompiler.structureGraph(ingraph, 0, getMonitor())
        return BlockGraph(outgraph)

    @property
    def varnodes(self):  # type: () -> list[Varnode]
        """Get all varnodes used in this function."""
        return [Varnode(raw) for raw in self.raw.locRange()]

    @property
    def symbols(self):  # type: () -> list[HighSymbol]
        """Get high symbols used in this function (including parameters)."""
        sm = self.raw.getLocalSymbolMap()
        return [HighSymbol(symbol) for symbol in sm.getSymbols()]

    @property
    def variables(self):  # type: () -> list[HighVariable]
        """Get high variables defined in this function."""
        result = []
        for sym in self.symbols:
            var = sym.variable
            if var is not None:
                result.append(var)
        return result

    def __eq__(self, other):  # type: (object) -> bool
        """Compare two high functions.

        Fun fact - Ghidra doesn't know how to do this."""
        if not isinstance(other, HighFunction):
            return False
        return self.function == other.function


class Reference(GhidraWrapper):
    @property
    def is_call(self):  # type: () -> bool
        """Return True if the reference is a call."""
        return self.reftype.is_call

    @property
    def is_jump(self):  # type: () -> bool
        """Return True if the reference is a jump."""
        return self.reftype.is_jump

    @property
    def reftype(self):  # type: () -> RefType
        """Return the type of reference."""
        return RefType(self.raw.getReferenceType())

    @property
    def from_address(self):  # type: () -> int
        """Return the address of the source of the reference."""
        return self.raw.getFromAddress().getOffset()

    @property
    def to_address(self):  # type: () -> int
        """Return the address of the target of the reference."""
        return self.raw.getToAddress().getOffset()

    @property
    def source(self):  # type: () -> SourceType
        return SourceType(self.raw.getSource())


def _reftype_placeholder():  # type: () -> RefType
    """Helper to solve the initialization order problem."""
    return None  # type: ignore


class RefType(GhidraWrapper):
    @property
    def has_fallthrough(self):  # type: () -> bool
        return self.raw.hasFallthrough()

    @has_fallthrough.setter
    def has_fallthrough(self, value):  # type: (bool) -> None
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


class FlowType(GhidraWrapper):
    """Wraps a Ghidra FlowType object"""

    # TODO is class this necessary? This is just a subclass of RefType.

    @property
    def is_call(self):  # type: () -> bool
        """Return True if this flow is a call."""
        return self.raw.isCall()

    @property
    def is_jump(self):  # type: () -> bool
        """Return True if this flow is a jump."""
        return self.raw.isJump()

    @property
    def is_computed(self):  # type: () -> bool
        """Return True if this flow is a computed jump."""
        return self.raw.isComputed()

    @property
    def is_conditional(self):  # type: () -> bool
        """Return True if this flow is a conditional jump."""
        return self.raw.isConditional()

    @property
    def is_unconditional(self):  # type: () -> bool
        """Return True if this flow is an unconditional jump."""
        return not self.is_conditional

    @property
    def is_terminal(self):  # type: () -> bool
        """Return True if this flow is a terminator."""
        return self.raw.isTerminal()

    @property
    def has_fallthrough(self):  # type: () -> bool
        """Return True if this flow has a fallthrough."""
        return self.raw.hasFallthrough()

    @property
    def is_override(self):  # type: () -> bool
        """Return True if this flow is an override."""
        return self.raw.isOverride()


class Operand:
    """Operand helper for instruction, may be a register, const or a list"""

    def __init__(self, operand):  # type: (str|int|list[int|str]) -> None
        self.raw = operand

    @property
    def is_register(self):  # type: () -> bool
        """Return True if this operand is a register."""
        return isinstance(self.raw, Str)

    @property
    def is_scalar(self):  # type: () -> bool
        """Return True if this operand is a scalar."""
        return isinstance(self.raw, (int, long))

    @property
    def is_list(self):  # type: () -> bool
        """Return True if this operand is a list."""
        return isinstance(self.raw, list)

    @property
    def register(self):  # type: () -> str
        """Gets this operand value as a register name"""
        if not isinstance(self.raw, (str)):
            raise RuntimeError("Operand {} is not a register".format(self.raw))
        return self.raw

    @property
    def scalar(self):  # type: () -> int
        """Gets this operand value as a scalar"""
        if not isinstance(self.raw, (int, long)):
            raise RuntimeError("Operand {} is not a scalar".format(self.raw))
        return self.raw

    @property
    def list(self):  # type: () -> list
        """Gets this operand value as a list"""
        if not isinstance(self.raw, list):
            raise RuntimeError("Operand {} is not a list".format(self.raw))
        return self.raw

    @property
    def value(self):  # type: () -> str|int|list[int|str]
        """Return internal representation of this operand - string, int or a list"""
        return self.raw


class Instruction(GhidraWrapper, BodyTrait):
    """Wraps a Ghidra Instruction object"""

    @staticmethod
    def get(address):  # type: (JavaObject|str|Addr) -> Instruction|None
        """Get an instruction at the address, or None if not found.

        Note: This will return None if the instruction is not defined in Ghidra
        at the given address. If you want to disassemble an address, not necessarily
        defined in Ghidra, try :func:`disassemble_at` instead.

        :param address: The address of the instruction.
        :return: The instruction at the address, or None if not found."""
        if can_resolve(address):
            raw = getInstructionAt(resolve(address))
        else:
            raw = address
        if raw is None:
            return None
        return Instruction(raw)

    @staticmethod
    def all():  # type: () -> list[Instruction]
        """Get all instruction defined in the current program."""
        raw_instructions = Program.current().getListing().getInstructions(True)
        return [Instruction(raw) for raw in raw_instructions]

    @staticmethod
    def create(address):  # type: (Addr) -> Instruction
        """Create an instruction at the given address.

        Note: this will force ghidra to disassemble at the given address,
        and return the created instruction. If you want to actually change the
        instruction at the given address, use `assemble_at` instead.

        If you want to just create an instruction object, use `assemble` method.

        :param address: The address where instruction should be created.
        """
        addr = resolve(address)
        disassemble(addr)
        return Instruction(addr)

    @property
    def mnemonic(self):  # type: () -> str
        """Get the mnemonic of this instruction."""
        return self.raw.getMnemonicString()

    @property
    def next(self):  # type: () -> Instruction
        """Get the next instruction."""
        return Instruction(self.raw.getNext())

    @property
    def previous(self):  # type: () -> Instruction
        """Get the previous instruction."""
        return Instruction(self.raw.getPrevious())

    prev = previous

    @property
    def flows(self):  # type: () -> list[int]
        """Get a set of possible flows (next executed addresses).

        Note: this DOES NOT INCLUDE a fallthrough. A strange design decision IMO,
        but I'm being faithful to Ghidra API."""
        return [addr.getOffset() for addr in self.raw.getFlows()]

    @property
    def all_flows(self):  # type: () -> list[int]
        """Get a set of possible flows (next executed addresses).

        Note: this INCLUDES fallthrough."""
        fallthrough = self.fallthrough
        return self.flows + ([fallthrough] if fallthrough else [])

    @property
    def pcode(self):  # type: () -> list[PcodeOp]
        """Get a list of Pcode operations that this instruction was parsed to"""
        return [PcodeOp(raw) for raw in self.raw.getPcode()]

    @property
    def output_varnodes(self):  # type: () -> list[Varnode]
        """Get a list of output (LOW) varnodes for this instruction."""
        return [op.output for op in self.pcode if op.output]

    @property
    def input_varnodes(self):  # type: () -> list[Varnode]
        """Get a list of output (LOW) varnodes for this instruction."""
        return [inp for op in self.pcode if op.output for inp in op.inputs]

    @property
    def high_pcode(self):  # type: () -> list[PcodeOp]
        """Get high Pcode for this instruction.

        WARNING: do not use this in a loop. Use Function.high_pcode instead."""
        return PcodeOp.get_high_pcode_at(self.address)

    @property
    def xrefs_from(self):  # type: () -> list[Reference]
        """Get a list of references from this instruction."""
        return [Reference(raw) for raw in self.raw.getReferencesFrom()]

    @property
    def xrefs_to(self):  # type: () -> list[Reference]
        """Get a list of references to this instruction."""
        return [Reference(raw) for raw in self.raw.getReferenceIteratorTo()]

    @property
    def bytes(self):  # type: () -> bytes
        """Get the bytes of this instruction."""
        return _bytes_from_bytelist(self.raw.getBytes())

    @property
    def length(self):  # type: () -> int
        """Get the length of this instruction in bytes."""
        return self.raw.getLength()

    def __len__(self):  # type: () -> int
        """Get the length of this instruction in bytes."""
        return self.length

    def __convert_operand(self, operand):  # type: (JavaObject) -> Operand
        """Convert an operand to a scalar or address."""
        from ghidra.program.model.address import Address  # type: ignore
        from ghidra.program.model.scalar import Scalar  # type: ignore

        if isinstance(operand, GhRegister):
            return Operand(_python_str(operand.getName()))
        elif isinstance(operand, Address):
            return Operand(operand.getOffset())
        elif isinstance(operand, Scalar):
            return Operand(operand.getValue())
        elif _is_array(operand):
            operands = [self.__convert_operand(o).raw for o in operand]  # type: ignore
            if len(operands) == 1:
                # Unwrap the operands if there is only one operand
                return Operand(operands[0])
            return Operand(operands)  # type: ignore (we know there are no nested lists)
        else:
            raise RuntimeError("Don't know how to read operand {}".format(operand))

    def operand(self, ndx):  # type: (int) -> Operand
        """Get the nth operand of this instruction as an object."""
        operand = self.raw.getOpObjects(ndx)
        return self.__convert_operand(operand)

    @property
    def address(self):  # type: () -> int
        """Get the address of this instruction."""
        return self.raw.getAddress().getOffset()

    @property
    def operands(self):  # type: () -> list[Operand]
        """Return operands as primitive values (int or a string representation).

        More specifically, this will convert constants and addresses into integers,
        and for registers the name will be returned.

        If you know operand type, call .scalar(), .register() or .list() instead."""
        return [self.operand(i) for i in range(self.raw.getNumOperands())]

    @property
    def operand_values(self):  # type: () -> list[int|str|list[int|str]]
        """Return operands as primitive values (int or a string representation).

        This is equivalent to calling .operands() and then calling .value()
        on each operand."""
        return [operand.value for operand in self.operands]

    @property
    def flow_type(self):  # type: () -> FlowType
        """Get the flow type of this instruction.

        For example, for x86 JMP this will return RefType.UNCONDITIONAL_JUMP"""
        return FlowType(self.raw.getFlowType())

    # int opIndex, Address refAddr, RefType type, SourceType sourceType
    def add_operand_reference(
        self, op_ndx, ref_addr, ref_type, src_type=SourceType.USER_DEFINED
    ):  # type: (int, Addr, RefType, SourceType) -> None
        """Add a reference to an operand of this instruction."""
        self.raw.addOperandReference(op_ndx, resolve(ref_addr), ref_type.raw, src_type)

    @property
    def body(self):  # type: () -> AddressSet
        """Get the address range this instruction."""
        return AddressSet.create(self.address, self.length)

    @property
    def has_fallthrough(self):  # type: () -> bool
        """Return true if this instruction has a fallthrough."""
        return self.raw.hasFallthrough()

    @property
    def fallthrough(self):  # type: () -> int|None
        """Get the fallthrough address (next address executed), if any.

        For normal instruction, this is the next instruction address. For jumps,
        this is None. Can be overriden by fallthrough override."""
        fall = self.raw.getFallThrough()
        if not fall:
            return None
        return fall.getOffset()

    def set_fallthrough_override(self, value):  # type: (Addr) -> None
        """Override the fallthrough address for this instruction.

        This sets the next instruction that will be executed after this
        instruction, assuming the current instruction doesn't jump anywhere.
        You can clear this with clear_fallthrough_override

        :param value: new fallthrough address"""
        self.raw.setFallThrough(resolve(value))

    def clear_fallthrough_override(self):  # type: () -> None
        """This clears the fallthrough override for this instruction.

        Alias for del self.fallthrough_override"""
        self.raw.clearFallThroughOverride()

    @property
    def has_fallthrough_override(self):  # type: () -> bool
        """Return true if this instruction fallthrough was overriden."""
        return self.raw.isFallThroughOverridden()

    def write_jumptable(self, targets):  # type: (list[Addr]) -> None
        """Provide a list of addresses where this instruction may jump.

        Warning: For this to work, the instruction must be a part of a function.

        This is useful for fixing unrecognised switches, for example.

        Note: the new switch instruction will use all references of type
        COMPUTED_JUMP already defined for the instruction
        (maybe we should clear them first?)."""

        targets = [resolve(addr) for addr in targets]

        for dest in targets:
            disassemble(dest)
            self.add_operand_reference(0, dest, RefType.COMPUTED_JUMP)

        func = Function.get(self.address)
        if func is None:
            raise RuntimeError("Instruction is not part of a function")

        targetlist = ArrayList([dest for dest in targets])
        jumpTab = JumpTable(toAddr(self.address), targetlist, True)
        jumpTab.writeOverride(func.raw)
        CreateFunctionCmd.fixupFunctionBody(Program.current(), func.raw, getMonitor())


class AddressRange(GhidraWrapper):
    """Wraps a Ghidra AddressRange object."""

    @property
    def addresses(self):  # type: () -> list[int]
        """Return the addresses in this range."""
        return [a.getOffset() for a in self.raw.getAddresses(True)]

    def __iter__(self):  # type: () -> Iterator[int]
        """Iterate over the addresses in this range."""
        return self.addresses.__iter__()

    @property
    def start(self):  # type: () -> int
        """Get the first address in this range."""
        return self.raw.getMinAddress().getOffset()

    @property
    def end(self):  # type: () -> int
        """Get the last address in this range."""
        return self.raw.getMaxAddress().getOffset()

    @property
    def length(self):  # type: () -> int
        """Get the length of this range."""
        return self.raw.getLength()

    def __len__(self):  # type: () -> int
        """Get the length of this range."""
        return self.length

    def contains(self, addr):  # type: (Addr) -> bool
        """Return True if the given address is in this range.

        :param addr: address to check"""
        return self.raw.contains(resolve(addr))

    def __contains__(self, addr):  # type: (Addr) -> bool
        """Return True if the given address is in this range.
        :param addr: address to check"""
        return self.contains(addr)

    @property
    def is_empty(self):  # type: () -> bool
        """Return True if this range is empty."""
        return self.raw.isEmpty()

    def __nonzero__(self):  # type: () -> bool
        """Return True if this range is not empty."""
        return not self.is_empty

    def __and__(self, other):  # type: (AddressRange) -> AddressRange
        """Return the intersection of this range and the given range."""
        return AddressRange(self.raw.intersect(other.raw))


class AddressSet(GhidraWrapper):
    """Wraps a Ghidra AddressSetView object."""

    @staticmethod
    def empty():  # type: () -> AddressSet
        """Create a new empty address set"""
        return AddressSet(GhAddressSet())

    @staticmethod
    def create(start, length):  # type: (Addr, int) -> AddressSet
        """Create a new AddressSet with given address and length."""
        addr = resolve(start)
        return AddressSet(GhAddressSet(addr, addr.add(length - 1)))

    @property
    def addresses(self):  # type: () -> list[int]
        """Return the addresses in this set."""
        return [a.getOffset() for a in self.raw.getAddresses(True)]

    @property
    def ranges(self):  # type: () -> list[AddressRange]
        return [AddressRange(r) for r in self.raw.iterator(True)]

    def __iter__(self):  # type: () -> Iterator[int]
        return self.addresses.__iter__()

    def contains(self, addr):  # type: (Addr) -> bool
        """Return True if the given address is in this range."""
        return self.raw.contains(resolve(addr))

    def __contains__(self, addr):  # type: (Addr) -> bool
        """Return True if the given address is in this range."""
        return self.contains(addr)

    @property
    def is_empty(self):  # type: () -> bool
        """Return True if this range is empty."""
        return self.raw.isEmpty()

    def __nonzero__(self):  # type: () -> bool
        """Return True if this range is not empty."""
        return not self.is_empty

    def __and__(self, other):  # type: (AddressSet) -> AddressSet
        """Return the intersection of this set and the given set."""
        return AddressSet(self.raw.intersect(other.raw))

    def __sub__(self, other):  # type: (AddressSet) -> AddressSet
        """Subtract the given set from this set."""
        return AddressSet(self.raw.subtract(other.raw))

    def __xor__(self, other):  # type: (AddressSet) -> AddressSet
        """Computes the symmetric difference of this set and the given set."""
        return AddressSet(self.raw.xor(other.raw))

    def __or__(self, other):  # type: (AddressSet) -> AddressSet
        """Computes the union of this set and the given set."""
        return AddressSet(self.raw.union(other.raw))

    def __get_highlighter(self):  # type: () -> Any
        tool = getState().getTool()
        service = tool.getService(ColorizingService)
        if service is None:
            raise RuntimeError("Cannot highlight without the ColorizingService")
        return service

    def highlight(self, color=HIGHLIGHT_COLOR):  # type: (Color) -> None
        service = self.__get_highlighter()
        service.setBackgroundColor(self.raw, color)

    def unhighlight(self):  # type: (Color) -> None
        service = self.__get_highlighter()
        service.clearBackgroundColor(self.raw)


class BasicBlock(AddressSet, BodyTrait):
    """Wraps a Ghidra CodeBlock object"""

    @staticmethod
    def _model(model):  # type: (str) -> Callable[[JavaObject], JavaObject]
        if model == "basic":
            return BasicBlockModel
        elif model == "simple":
            return SimpleBlockModel
        else:
            raise ValueError("Unsupported model type: %s" % model)

    @staticmethod
    def get(
        raw_or_address, model="basic"
    ):  # type: (JavaObject|str|Addr, str) -> BasicBlock|None
        """Get a BasicBlock object containing the given address, or return None.

        This function is tolerant and will accept different types of arguments:
        * address as int
        * Address object
        * symbol as string (will be resolved)
        * BasicBlock object (wrapped or unwrapped)

        :param raw_or_address: find basicblock that contains the given address.
        :param model: Ghidra supports different types of basic block "models".
        Supported options are "basic" and "simple"."""

        if raw_or_address is None:
            return None
        if can_resolve(raw_or_address):
            block_model = BasicBlock._model(model)(Program.current())
            addr = try_resolve(raw_or_address)
            if addr is None:
                return None
            raw = block_model.getFirstCodeBlockContaining(addr, TaskMonitor.DUMMY)
            if raw is None:
                return None
        else:
            raw = raw_or_address
        return BasicBlock(raw)

    @staticmethod
    def all(model="basic"):  # type: (str) -> list[BasicBlock]
        """Get a list of all basic blocks in the program."""
        block_model = BasicBlock._model(model)(Program.current())
        return [BasicBlock(b) for b in block_model.getCodeBlocks(TaskMonitor.DUMMY)]

    @property
    def name(self):  # type: () -> str
        """Get the name of this basic block.

        Return the symbol at the start of this basic block, if any. Otherwise,
        return the address of the first instruction as string."""
        return self.raw.getName()

    @property
    def address(self):  # type: () -> int
        """Get the address of the first instruction in this basic block."""
        return self.start_address

    @property
    def start_address(self):  # type: () -> int
        """Get the address of the first instruction in this basic block."""
        return self.raw.getMinAddress().getOffset()

    @property
    def end_address(self):  # type: () -> int
        """Get the address of the last byte in this basic block.

        Note: this is not the address of the last instruction.
        Note: end_address - start_address is equal to length - 1. For example,
        for one-byte basic block, start_address == end_address."""
        return self.raw.getMaxAddress().getOffset()

    @property
    def length(self):  # type: () -> int
        """Get the length of this basic block in bytes."""
        return self.end_address - self.start_address + 1

    @property
    def bytes(self):  # type: () -> bytes
        """Get the bytes of this basic block.

        :return: bytes of this basic block."""
        return read_bytes(self.start_address, self.length)

    @property
    def instructions(self):  # type: () -> list[Instruction]
        """Get a list of instructions in this basic block."""
        result = []
        instruction = getInstructionAt(resolve(self.start_address))
        while instruction and instruction.getAddress().getOffset() <= self.end_address:
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

    @property
    def body(self):  # type: () -> AddressSet
        """Get the address set of this basic block

        Technically BasicBlock (CodeBlock) is is already an AddressSet,
        but I think this is a useful distinction to keep."""
        return AddressSet(self.raw)

    @property
    def flow_type(self):  # type: () -> FlowType
        """Get the flow type of this basic block.

        In other words, if any weird things with control flow are happening
        in this node."""
        return FlowType(self.raw.getFlowType())

    def __eq__(self, other):  # type: (object) -> bool
        """Compare two basic blocks for equality.

        Apparently Ghidra doesn't know how to do this"""
        if not isinstance(other, BasicBlock):
            return False
        # This is not fully correct, but more correct than the default.
        return self.address == other.address


class Variable(GhidraWrapper):
    """Wraps a Ghidra Variable object"""

    @property
    def name(self):  # type: () -> str
        """Get the name of this variable"""
        return self.raw.getName()

    @name.setter
    def name(self, name):  # type: (str) -> None
        """Rename this variable"""
        self.rename(name, SourceType.USER_DEFINED)

    def rename(
        self, name, source=SourceType.USER_DEFINED
    ):  # type: (str, SourceType) -> None
        """Rename this variable"""
        self.raw.setName(name, source)

    @property
    def data_type(self):  # type: () -> DataType
        """Get the data type of this variable"""
        return DataType(self.raw.getDataType())

    @data_type.setter
    def data_type(
        self, data_type, source=SourceType.USER_DEFINED
    ):  # type: (DataType, SourceType) -> None
        """Set the data type of this variable"""
        self.raw.setDataType(data_type.raw, source)

    @property
    def is_valid(self):  # type: () -> bool
        """Check if this variable is valid"""
        return self.raw.isValid()

    @property
    def comment(self):  # type: () -> str|None
        """ "Get the comment for this variable"""
        return self.raw.getComment()

    @comment.setter
    def comment(self, name):  # type: (str|None) -> None
        """Set the comment for this variable"""
        self.set_comment(name)

    def set_comment(self, comment):  # type: (str|None) -> None
        """Set the comment for this variable"""
        self.raw.setComment(comment)

    @property
    def is_auto(self):  # type: () -> bool
        """Check if this variable is an automatic parameter.

        Some parameters are "hidden parameters" dictated by the calling
        convention. This method returns true for such paramteters."""
        return self.raw.getVariableStorage().isAutoStorage()

    @property
    def is_forced_indirect(self):  # type: () -> bool
        """Check if this variable was forced to be a pointer by calling convention"""
        return self.raw.getVariableStorage().isForcedIndirect()

    @property
    def has_bad_storage(self):  # type: () -> bool
        """Check if this variable has bad storage (could not be resolved)"""
        return self.raw.getVariableStorage().isBadStorage()

    @property
    def is_unassigned_storage(self):  # type: () -> bool
        """Check if this variable has no assigned storage (varnodes)"""
        return self.raw.getVariableStorage().isUnassignedStorage()

    @property
    def is_void(self):  # type: () -> bool
        """Check if this variable is of type void"""
        return self.raw.getVariableStorage().isVoidStorage()

    @property
    def stack_offfset(self):  # type: () -> int
        """Get the stack offset of this variable."""
        return self.raw.getVariableStorage().getStackOffset()

    @property
    def is_constant(self):  # type: () -> bool
        """Check if this variable consists of a single constant-space varnode"""
        return self.raw.getVariableStorage().isConstantStorage()

    @property
    def is_hash(self):  # type: () -> bool
        """Check if this variable consists of a single hash-space varnode."""
        return self.raw.getVariableStorage().isHashStorage()

    @property
    def is_stack(self):  # type: () -> bool
        """Check if this variable is a stack variable"""
        return self.raw.isStackVariable()

    @property
    def is_memory(self):  # type: () -> bool
        """Check if this variable is stored in memory"""
        return self.raw.isMemoryVariable()

    @property
    def is_unique(self):  # type: () -> bool
        """Check if this variable is of type unique"""
        return self.raw.isUniqueVariable()

    @property
    def is_compound(self):  # type: () -> bool
        """Check if this variable is a compound variable"""
        return self.raw.isCompoundVariable()

    @property
    def symbol(self):  # type: () -> Symbol
        """Get the symbol for this variable"""
        return Symbol(self.raw.getSymbol())

    @property
    def source(self):  # type: () -> SourceType
        """Get the source type of this variable"""
        return SourceType(self.raw.getSource())

    @property
    def varnode(self):  # type: () -> Varnode
        """Get the first varnode associated with this variable.

        Warning: there may be more than one varnode associated with a variable."""
        return Varnode(self.raw.getFirstStorageVarnode())

    @property
    def varnodes(self):  # type: () -> list[Varnode]
        """Get all varnodes associated with this variable."""
        storage = self.raw.getVariableStorage()
        return [Varnode(x) for x in storage.getVarnodes()]

    @property
    def is_register(self):  # type: () -> bool
        """Check if this variable consists of a single register."""
        return self.raw.isRegisterVariable()

    @property
    def register(self):  # type: () -> str
        """Get the register associated with this variable.

        Raises an exception if this variable is not a register variable."""
        reg = self.raw.getRegister()
        if not reg:
            raise ValueError("Variable is not a register variable")
        return reg.getName()

    @property
    def function(self):  # type: () -> Function
        """Get the function associated with this variable."""
        return Function(self.raw.getFunction())


class Parameter(Variable):
    """Wraps a Ghidra Parameter object."""

    @property
    def ordinal(self):  # type: () -> int
        """Returns the ordinal of this parameter."""
        return self.raw.getOrdinal()

    @property
    def formal_data_type(self):  # type: () -> DataType
        """Returns the formal data type of this parameter."""
        return DataType(self.raw.getFormalDataType())


class FunctionCall(BodyTrait):
    """Represents a function call at a given location in the program.

    Can be used to get the function being called and the parameters passed to it."""

    def __init__(self, function, address):  # type: (Function, Addr) -> None
        self.called_function = function
        self._address = resolve(address)

    @property
    def address(self):  # type: () -> int
        return self._address.getOffset()

    @property
    def caller(self):  # type: () -> Function|None
        """Get the function where this function call takes place."""
        return Function.get(self._address)

    calling_function = caller

    @property
    def instruction(self):  # type: () -> Instruction
        return Instruction(self._address)

    @property
    def callee(self):  # type: () -> Function
        """Get the function being called."""
        return self.called_function

    def infer_context(self):  # type: () -> Emulator
        """Emulate the code before this function call, and return the state.

        The goal of this function is to recover the state of the CPU
        before the function call, as well as possible. This will work well when
        parameters are constants written just before the call, for example:

            mov eax, 30
            mov ebx, DAT_encrypted_string
            call decrypt_string

        Then recovering eax is as simple as call.infer_context()["eax"]."""
        basicblock = BasicBlock(self._address)
        return Emulator.new(basicblock.start_address, self._address)

    @property
    def high_pcodeop(self):  # type: () -> PcodeOp|None
        """Get the high-level PcodeOp for this function call.

        High-level Pcode `call` ops have the parameters resolved, so we
        can use them to read them when analysing Pcode.

        Warning: this works on decompiled functions only, so it will work
          if the call is done from a region not recognised as function.
        Warning: this method needs to decompile the function, and is therefore slow."""
        for pcode_op in PcodeOp.get_high_pcode_at(self._address):
            if pcode_op.opcode != pcode_op.CALL:
                continue
            return pcode_op

        raise RuntimeError("No CALL at {}".format(self.address))

    @property
    def high_varnodes(self):  # type: () -> list[Varnode]
        """Get a list of the arguments passed to this function call, as high varnodes.

        In other words, decompile the function, and return the varnodes associated with
        the function parameters, as seen by Ghidra decompiler.

        Warning: this works on decompiled functions only, so it will work
          if the call is done from a region not recognised as function.
        Warning: this method needs to decompile the function, and is therefore slow."""
        op = self.high_pcodeop
        if not op:
            return []
        return op.inputs[1:]  # skip function addr

    def infer_args(self):  # type: () -> list[int|None]
        """Get a list of the arguments passed to this function call, as integers.

        This method tries to get arguments of this function, as seen by Ghidra
        decompiler. A limited symbolic execution is performed to resolve the pointers.
        If it's not possible to get an argument, None is stored in its place.

        Warning: this works on decompiled functions only, so it will work
          if the call is done from a region not recognised as function.
        Warning: this method needs to decompile the function, and is therefore slow.
        """
        args = []
        for varnode in self.high_varnodes:
            if varnode.value is not None:
                args.append(varnode.value)
            else:
                args.append(None)
        return args

    @property
    def body(self):
        return self.instruction.body


class ClangTokenGroup(GhidraWrapper):
    """Represents a group of clang tokens from a decompiler.

    Warning: Currently this class is experimental, and should not be relied upon,
    except to get the Java object (with .raw) or maybe dump (.dump())."""

    def _cleanup(self, token):  # type: (JavaObject) -> JavaObject
        new = GhClangTokenGroup(token.Parent())
        for token in list(token.iterator()):
            if isinstance(token, (ClangCommentToken, ClangBreak)):
                continue
            if isinstance(token, ClangSyntaxToken):
                if not token.getText() or token.getText().isspace():
                    continue
            if isinstance(token, GhClangTokenGroup):
                token = self._cleanup(token)
            new.AddTokenGroup(token)
        return new

    @property
    def cleaned(self):  # type: () -> ClangTokenGroup
        """Remove all whitespace and comments from this token group, recursively."""
        return ClangTokenGroup(self._cleanup(self.raw))

    def _dump(self, token, indent=0):  # type: (JavaObject, int) -> None
        if isinstance(token, GhClangTokenGroup):
            print("{}[group]".format(indent * "  ", token.__class__.__name__))
            for child in token.iterator():
                self._dump(child, indent + 1)
        else:
            print("{}{} ({})".format(indent * "  ", token, token.__class__.__name__))

    def dump(self):  # type: () -> None
        self._dump(self.raw)


class SymbolicPropogator(GhidraWrapper):
    """Wraps SymbolicPropogator. Can be used to get known values at various
    locations in a given function (or outside of a function)"""

    @staticmethod
    def create():
        return SymbolicPropogator(GhSymbolicPropogator(Program.current()))

    def flow_constants(
        self, addr, body, evaluator
    ):  # type: (Addr, AddressSet, JavaObject) -> None
        """Flow constants from the given address in the given body

        :param addr: The address to start from
        :param body: The body where constants should be propagated
        :param evaluator: The evaluator to use for the propagation"""
        addr = resolve(addr)
        self.raw.flowConstants(addr, body.raw, evaluator, False, getMonitor())

    def register_at(self, addr, register):  # type: (Addr, Reg) -> int|None
        """Get a known register value at the given address (or None)

        Warning: this value is signed.

        :param addr: The address to get a register value at
        :param register: The register to get a value for
        :return: The value of the register at the given address, or None if the
        register is not known at that address"""
        addr = resolve(addr)
        reg = Register(register)
        value = self.raw.getRegisterValue(addr, reg.raw)
        if not value or value.isRegisterRelativeValue():
            # This never happens in my tests, so I just won't handle register-relative
            # values. I don't know when this can ever happen.
            return None
        return value.value


class Function(GhidraWrapper, BodyTrait):
    """Wraps a Ghidra Function object."""

    UNDERLYING_CLASS = GhFunction

    @staticmethod
    def get(addr):  # type: (JavaObject|str|Addr) -> Function|None
        """Return a function at the given address, or None if no function
        exists there."""
        if isinstance(addr, GhFunction):
            return Function(addr)
        if isinstance(addr, Function):
            return Function(addr.raw)
        addr = try_resolve(addr)
        if addr is None:
            return None
        raw = Program.current().getListing().getFunctionContaining(addr)
        if raw is None:
            return None
        return Function(raw)  # type: ignore

    @staticmethod
    def all():  # type: () -> list[Function]
        """Return all functions in the current program."""
        raw_functions = Program.current().getFunctionManager().getFunctions(True)
        return [Function(f) for f in raw_functions]

    @staticmethod
    def create(address, name):  # type: (Addr, str) -> Function
        """Create a new function at the given address with the given name."""
        func = createFunction(resolve(address), name)
        return Function(func)

    @property
    def return_type(self):  # type: () -> DataType
        """Get the return type of this function."""
        return DataType(self.raw.getReturnType())

    @property
    def return_variable(self):  # type: () -> Parameter
        """Get the variable representing a return value of this function."""
        return Parameter(self.raw.getReturn())

    @property
    def entrypoint(self):  # type: () -> int
        """Get the entrypoint of this function."""
        return self.raw.getEntryPoint().getOffset()

    @property
    def address(self):  # type: () -> int
        """Get the address of this function."""
        return self.entrypoint

    @property
    def exitpoints(self):  # type: () -> list[int]
        """Get a list of exit points for the function.

        This will return a list of addresses of function terminators. For example,
        if a function has two RETs, this function will return their addresses."""
        return [i.address for i in self.instructions if i.flow_type.is_terminal]

    @property
    def name(self):  # type: () -> str
        """Get the name of this function."""
        return self.raw.getName()

    @property
    def comment(self):  # type: () -> str|None
        """Get the comment of this function, if any."""
        return self.raw.getComment()

    def set_comment(self, comment):  # type: (str|None) -> None
        """Set the comment of this function."""
        self.raw.setComment(comment)

    @property
    def is_thunk(self):  # type: () -> bool
        """Return True if this function is a thunk."""
        return self.raw.isThunk()

    @property
    def is_external(self):  # type: () -> bool
        """Return True if this function is external."""
        return self.raw.isExternal()

    @property
    def repeatable_comment(self):  # type: () -> str|None
        """Get the repeatable comment of this function, if any."""
        return self.raw.getRepeatableComment()

    def set_repeatable_comment(self, comment):  # type: (str|None) -> None
        """Set the repeatable comment of this function."""
        self.raw.setRepeatableComment(comment)

    @property
    def parameters(self):  # type: () -> list[Parameter]
        """Get the parameters of this function."""
        return [Parameter(raw) for raw in self.raw.getParameters()]

    def add_named_parameter(self, datatype, name):  # type: (DataT, str) -> None
        """Add a parameter with a specified name to this function.

        Warning: adding a register parameter will switch the function into
        custom storage mode. Adding named parameters in custom storage is not
        implemented"""
        if self.raw.hasCustomVariableStorage():
            raise ValueError(
                "Sorry, adding named parameters is not implemented "
                "for functions with custom storage"
            )
        data = DataType(datatype)
        param = ParameterImpl(name, data.raw, 0, Program.current())
        self.raw.addParameter(param, SourceType.USER_DEFINED)

    def add_register_parameter(
        self, datatype, register, name
    ):  # type: (DataT, Reg, str) -> None
        """Add a parameter stored in a specified register to this function.

        Warning: adding a register parameter will switch the function into
        custom storage mode. Adding named parameters in custom storage will
        not work anymore"""
        if not self.raw.hasCustomVariableStorage():
            self.raw.setCustomVariableStorage(True)
        reg = Register(register)
        data = DataType(datatype)
        param = ParameterImpl(name, data.raw, reg.raw, Program.current())
        self.raw.addParameter(param, SourceType.USER_DEFINED)

    def fixup_body(self):  # type: () -> bool
        """Fixup the function body: follow control flow and add thunks."""
        return CreateFunctionCmd.fixupFunctionBody(
            Program.current(), self.raw, getMonitor()
        )

    @property
    def local_variables(self):  # type: () -> list[Variable]
        """Get the local variables of this function."""
        return [Variable(raw) for raw in self.raw.getLocalVariables()]

    @property
    def variables(self):  # type: () -> list[Variable]
        """Get all variables defined in this function."""
        return [Variable(raw) for raw in self.raw.getAllVariables()]

    @property
    def varnodes(self):  # type: () -> list[Varnode]
        """Get all varnodes associated with a variable in this function."""
        varnodes = []
        for var in self.variables:
            varnodes.extend(var.varnodes)
        return varnodes

    @property
    def high_variables(self):  # type: () -> list[HighVariable]
        """Get all variables defined in this function.

        Warning: this method needs to decompile the function, and is therefore slow."""
        return self.high_function.variables

    @property
    def stack(self):  # type: () -> list[Variable]
        """Get the defined stack variables (both parameters and locals)."""
        raw_vars = self.raw.getStackFrame().getStackVariables()
        return [Variable(raw) for raw in raw_vars]

    def rename(self, name):  # type: (str) -> None
        """Change the name of this function."""
        self.raw.setName(name, SourceType.USER_DEFINED)

    @property
    def instructions(self):  # type: () -> list[Instruction]
        """Get the assembler instructions for this function."""
        listing = Program.current().getListing()
        raw_instructions = listing.getInstructions(self.raw.getBody(), True)
        return [Instruction(raw) for raw in raw_instructions]

    @property
    def xrefs(self):  # type: () -> list[Reference]
        """Get the references to this function."""
        raw_refs = getReferencesTo(resolve(self.entrypoint))
        return [Reference(raw) for raw in raw_refs]

    xrefs_to = xrefs

    @property
    def xref_addrs(self):  # type: () -> list[int]
        """Get the source addresses of references to this function."""
        return [xref.from_address for xref in self.xrefs]

    @property
    def callers(self):  # type: () -> list[Function]
        """Get all functions that call this function."""
        return [
            Function(raw) for raw in self.raw.getCallingFunctions(TaskMonitor.DUMMY)
        ]

    @property
    def called(self):  # type: () -> list[Function]
        """Get all functions that are called by this function."""
        return [Function(raw) for raw in self.raw.getCalledFunctions(TaskMonitor.DUMMY)]

    @property
    def fixup(self):  # type: () -> str|None
        """Get the fixup of this function."""
        return self.raw.getCallFixup()

    @fixup.setter
    def fixup(self, fixup):  # type: (str|None) -> None
        """Set the fixup of this function.

        :param fixup: The new fixup to set."""
        self.raw.setCallFixup(fixup)

    @property
    def calls(self):  # type: () -> list[FunctionCall]
        """Get all function calls to this function."""
        calls = []
        for ref in self.xrefs:
            if ref.is_call:
                calls.append(FunctionCall(self, ref.from_address))
        return calls

    @property
    def basicblocks(self):  # type: () -> list[BasicBlock]
        """Get the basic blocks of this function."""
        block_model = BasicBlockModel(Program.current())
        blocks = block_model.getCodeBlocksContaining(
            self.raw.getBody(), TaskMonitor.DUMMY
        )
        return [BasicBlock(block) for block in blocks]

    def _decompile(self, simplify="decompile"):  # type: (str) -> JavaObject
        """Decompile this function (internal helper)."""
        decompiler = DecompInterface()
        decompiler.openProgram(Program.current())
        decompiler.setSimplificationStyle(simplify)
        decompiled = decompiler.decompileFunction(self.raw, 5, TaskMonitor.DUMMY)
        decompiler.closeProgram()
        decompiler.dispose()
        if decompiled is None:
            raise RuntimeError("Failed to decompile function {}".format(self.name))
        return decompiled

    def decompile(self):  # type: () -> str
        """Get decompiled C code for the function as string."""
        decompiled = self._decompile()
        return decompiled.getDecompiledFunction().getC()

    @property
    def clang_tokens(self):  # type: () -> ClangTokenGroup
        """Get clang tokens for the decompiled function.

        This returns a ClangTokenGroup object. TODO: wrap the return value."""
        decompiled = self._decompile()
        return ClangTokenGroup(decompiled.getCCodeMarkup())

    @property
    def high_function(self):  # type: () -> HighFunction
        """Decompile this function, and return a high-level function.

        Warning: this method needs to decompile the function, and is therefore slow."""
        return self.get_high_function()

    def get_high_function(self, simplify="decompile"):  # type: (str) -> HighFunction
        """Decompile this function, and return a high-level function.

        Warning: this method needs to decompile the function, and is therefore slow.

        :simplify: the simplification style to use.
        See DecompilerInterface.setSimplificationStyle."""
        decompiled = self._decompile(simplify)
        return HighFunction(decompiled.getHighFunction())

    def get_high_pcode(self, simplify="decompile"):  # type: (str) -> list[PcodeOp]
        """Decompile this function, and return its high-level Pcode.

        Warning: this method needs to decompile the function, and is therefore slow.

        :simplify: the simplification style to use.
        See DecompilerInterface.setSimplificationStyle."""
        return self.get_high_function(simplify).pcode

    @property
    def pcode_tree(self):  # type: () -> BlockGraph
        """Get an AST-like representation of the function's Pcode.

        Warning: this method needs to decompile the function, and is therefore slow."""
        return self.get_high_function().pcode_tree

    @property
    def pcode(self):  # type: () -> list[PcodeOp]
        """Get the (low-level) Pcode for this function."""
        result = []
        for block in self.basicblocks:
            result.extend(block.pcode)
        return result

    @property
    def high_pcode(self):  # type: () -> list[PcodeOp]
        """Get the (high-level) Pcode for this function.

        Warning: this method needs to decompile the function, and is therefore slow."""
        return self.get_high_pcode()

    @property
    def high_basicblocks(self):  # type: () -> list[PcodeBlock]
        """Get the (high-level) Pcode basic blocks for this function.

        Warning: this method needs to decompile the function, and is therefore slow."""
        return self.high_function.basicblocks

    def get_high_pcode_at(self, address):  # type: (Addr) -> list[PcodeOp]
        """Get the high-level Pcode at the given address.

        Do not use this function in a loop! Better decompile the whole function first.

        Warning: this method needs to decompile the function, and is therefore slow.

        :param address: the address to get the Pcode for."""
        return self.get_high_function().get_pcode_at(address)

    @property
    def high_symbols(self):  # type: () -> list[HighSymbol]
        """Get the high-level symbols for this function.

        Warning: this method needs to decompile the function, and is therefore slow."""
        return self.get_high_function().symbols

    @property
    def primary_symbols(self):  # type: () -> list[Symbol]
        """Get the primary symbols for this function."""
        symtable = Program.current().getSymbolTable()
        syms = symtable.getPrimarySymbolIterator(self.raw.getBody(), True)
        return [Symbol(s) for s in syms]

    @property
    def symbols(self):  # type: () -> list[Symbol]
        """Get the symbols for this function.

        Unfortunately, the implementation of this function has to iterate over
        all function addresses (because SymbolTable doesn't export the right method),
        so it may be quite slow when called frequently. Consider using primary_symbols
        if adequate."""
        body = self.raw.getBody()
        symbols = []
        symtable = Program.current().getSymbolTable()
        for rng in body:
            for addr in rng:
                symbols.extend(symtable.getSymbols(addr))
        return [Symbol(raw) for raw in symbols]

    @property
    def body(self):  # type: () -> AddressSet
        """Get the set of addresses of this function."""
        return AddressSet(self.raw.getBody())

    @property
    def control_flow(self):  # type: () -> Graph[BasicBlock]
        """Get the control flow graph of this function.

        In other words, get a graph that represents how the control flow
        can move between basic blocks in this function."""
        return Graph.construct(self.basicblocks, lambda v: v.destinations)

    def emulate(self, *args, **kwargs):  # type: (int, Emulator) -> Emulator
        """Emulate the function call with given args, and return final emulation state.

        The arguments are passed using a calling convention defined in Ghidra. If
        you want to use a different calling convention, or do additional setup,
        you have to use the Emulator class directly.

        You can pass your own emulator using the `emulator` kwarg. You can use this
        to do a pre-call setup (for example, write string parameters to memory). But
        don't use this to change call parameters, as they are always overwriten.

            >>> fnc = Function("ResolveName")
            >>> emu = fnc.emulate(1379010213)
            >>> emu.read_unicode(emu["eax"])
            "HKEY_CLASSES_ROOT"

        :param args: The arguments to pass to the function.
        :param kwargs: pass `emulator` kwarg to use the provided emulator
          (default: create a new one)."""
        if "emulator" in kwargs:
            # Jython doesn't support keyword arguments after args, apparently
            emulator = kwargs["emulator"]
        else:
            emulator = Emulator()

        if len(args) != len(self.raw.getParameters()):
            raise ValueError(
                "Wrong number of arguments for {} - got {} expected {}".format(
                    self.name, len(args), len(self.raw.getParameters())
                )
            )

        for param, value in zip(self.parameters, args):
            emulator.write_varnode(param.varnode, value)

        emulator.emulate(self.entrypoint, stop_when=lambda emu: emu.pc not in self.body)
        return emulator

    def emulate_simple(self, *args, **kwargs):  # type: (int, Emulator) -> int
        """Emulate the function call with given args, and return the return value.

        The arguments are passed using a calling convention defined in Ghidra. If
        you want to use a different calling convention, or do additional setup,
        you have to use the Emulator class directly.

        You can pass your own emulator using the `emulator` kwarg. You can use this
        to do a pre-call setup (for example, write string parameters to memory). But
        don't use this to change call parameters, as they are always overwriten.

        Note: the name is not great, but I can't think of a better name that is
        not also very long.

            >>> fnc = Function("CustomHash")
            >>> fnc.emulate_simple("HKEY_CLASSES_ROOT")
            1379010213

        :param args: The arguments to pass to the function.
        :param kwargs: pass `emulator` kwarg to use the provided emulator
          (default: create a new one)."""
        context = self.emulate(*args, **kwargs)
        return context.read_varnode(self.return_variable.varnode)

    def symbolic_context(self):  # type: () -> SymbolicPropogator
        """Returns a SymbolicPropogator instance for this function.

        This can be used to get a known values of registers at various addresses.

            >>> fnc = Function(0x004061EC)
            >>> ctx = fnc.symbolic_context()
            >>> print(ctx.register(0x004061fb, "eax"))

        TODO: This method should implement a hack described in
        https://github.com/NationalSecurityAgency/ghidra/issues/3581
        because built-in Ghidra symbolic propagator doesn't support memory accesses.

        :return: a SymbolicPropogator instance with this function context."""
        propagator = SymbolicPropogator.create()
        evaluator = ConstantPropagationContextEvaluator(getMonitor())
        propagator.flow_constants(self.entrypoint, self.body, evaluator)
        return propagator


class Symbol(GhidraWrapper):
    """Wraps a Ghidra Symbol object."""

    @staticmethod
    def resolve_thunk_if_exists(external_symbol):  # type: (JavaObject) -> JavaObject
        """Returns a function thunk leading to a passed external symbol, if it exists.

        If there is no function thunk, original symbol is returned.

        Why is this ugly thing here? Well, we want to support external symbols,
        especially external functions. Thunks are much more useful for us when
        thinking in context of the analysed program - when Linux program calls
        `printf` it jumps to the appropriate `printf` thunk, not to libc
        directly. So this is the location that we want to patch/hook/trace/etc when
        thinking about printf. But the thing is that Ghidra SymbolTable API will
        not even return thunks! So we trace the external function references, and
        return the first (almost certainly only) Thunk reference.

        :param external_symbol: Symbol to find thunk for (if it exists).
        """
        xrefs = list(external_symbol.getReferences())
        for xref in xrefs:
            if xref.getReferenceType() == GhRefType.THUNK:
                addr = xref.getFromAddress()
                thunk = Program.current().getSymbolTable().getPrimarySymbol(addr)
                if thunk is not None:
                    return thunk
        return external_symbol

    @staticmethod
    def resolve_external(external_symbol):  # type: (JavaObject) -> int
        """Resolves an external address to a RAM location, if possible.

        If the symbol has no RAM location, just return its offset.

        Why is this ugly thing here? Again, we want to support external symbols, and
        we are interested in their RAM address in the program address space. In some
        cases, Ghidra will give an external address a "location" in the RAM space.
        So, for example, if current program jumps to that external function (or read
        that external variable etc), it will read that location as far as Ghidra is
        concerned (for example, Emulator will use it for calls). This is important
        for emulating Windows binaries, that use address tables for imports.

        :param external_symbol: External symbol to resolve."""
        external_manager = Program.current().getExternalManager()
        ram_addr = external_manager.getExternalLocation(external_symbol).getAddress()
        if ram_addr:
            return ram_addr.getOffset()
        return external_symbol.getAddress().getOffset()

    @staticmethod
    def get(raw_or_name):  # type: (JavaObject|str|Addr) -> Symbol|None
        """Get a symbol with the provided name or at the provided address.

        Return None if the symbol was not found.

        Note: when resolving by name, local symbols take precedence over external ones
        (in particular for function thunks - in contrast to Ghidra default behaviour).

        :param raw_or_name: a Ghidra Java object, a string, or an address."""
        if isinstance(raw_or_name, str):
            symbol_iterator = Program.current().getSymbolTable().getSymbols(raw_or_name)
            symbols = collect_iterator(symbol_iterator)
            if not symbols:
                return None
            raw = symbols[0]
            if raw.isExternal():
                raw = Symbol.resolve_thunk_if_exists(raw)
        elif can_resolve(raw_or_name):
            raw = (
                Program.current()
                .getSymbolTable()
                .getPrimarySymbol(resolve(raw_or_name))
            )
            if not raw:
                return None
        else:
            raw = raw_or_name
        return Symbol(raw)

    @staticmethod
    def all():  # type: () -> list[Symbol]
        """Get all symbols defined in the program."""
        symbol_iterator = Program.current().getSymbolTable().getAllSymbols(True)
        symbols = collect_iterator(symbol_iterator)
        return [Symbol(s) for s in symbols]

    @staticmethod
    def create(
        address, name, source=SourceType.USER_DEFINED
    ):  # type: (Addr, str, SourceType) -> Symbol
        """Create a new symbol (also called label) at the given address.

        :param address: the address where to create the symbol.
        :param name: the name of the symbol.
        :param source: the source type for the new symbol."""
        raw = createLabel(resolve(address), name, False, source)
        return Symbol(raw)

    @staticmethod
    def remove(address, name):  # type: (Addr, str) -> None
        """Remove the symbol with the given name at the given address.

        :param address: the address of the symbol to remove.
        :param name: the name of the symbol to remove."""
        removeSymbol(resolve(address), name)

    @property
    def address(self):  # type: () -> int
        """Get the address of this symbol."""
        if self.is_external:
            return Symbol.resolve_external(self.raw)
        return self.raw.getAddress().getOffset()

    @property
    def name(self):  # type: () -> str
        """Get the name of this symbol."""
        return self.raw.getName()

    @property
    def name_with_namespace(self):  # type: () -> str
        """Get the fully qualified name of this symbol."""
        return self.raw.getName(True)

    @property
    def xrefs(self):  # type: () -> list[Reference]
        """Get a list of references to this symbol."""
        return [Reference(raw) for raw in self.raw.getReferences()]

    xrefs_to = xrefs

    @property
    def xref_addrs(self):  # type: () -> list[int]
        """Get the addresses of all references to this symbol."""
        return [xref.from_address for xref in self.xrefs]

    def set_type(self, datatype):  # type: (DataT) -> None
        """Set the data type of this symbol."""
        Program.create_data(self.address, datatype)

    def delete(self):  # type: () -> None
        """Delete this symbol."""
        self.raw.delete()

    def rename(
        self, new_name, source=SourceType.USER_DEFINED
    ):  # type: (str, SourceType) -> None
        """Rename this symbol.

            >>> main = Symbol.get("main")
            >>> main.rename("main_renamed")
            >>> main.name
            'main_renamed'

        :param new_name: the new name of the symbol."""
        self.raw.setName(new_name, source)

    @property
    def is_external(self):  # type: () -> bool
        """Return true if this symbol is external, otherwise false.

        Note: when resolving by name, local symbols take precedence over external ones
        (in particular for function thunks - in contrast to Ghidra default behaviour).

        :return: true if the symbol is external"""
        return self.raw.isExternal()


class DataType(GhidraWrapper):
    @staticmethod
    def get(name_or_raw):  # type: (DataT) -> DataType|None
        """Gets a data type by name, or returns None if not found.

        Warning: this method is relatively slow, since it scans
        all data types in all data type managers.

            >>> DataType.get("int")
            int

        :param name_or_raw: the name of the data type
        :return: the data type, or None if not found"""
        if not isinstance(name_or_raw, Str):
            return DataType(name_or_raw)

        for datatype in DataType.all():
            if datatype.name == name_or_raw:
                return DataType(datatype)
        return None

    @staticmethod
    def all(only_local=False):  # type: (bool) -> list[DataType]
        """Get all data types

        :param only_local: if True, return only local data types. Otherwise,
          will scan all data types in all data type managers."""
        datatypes = list(Program.current().getDataTypeManager().getAllDataTypes())
        if not only_local:
            managers = (
                getState()
                .getTool()
                .getService(DataTypeManagerService)
                .getDataTypeManagers()
            )
            for manager in managers:
                for datatype in manager.getAllDataTypes():
                    datatypes.append(datatype)
        return [DataType(raw) for raw in datatypes]

    @property
    def name(self):  # type: () -> str
        """Get a name of this data type

            >>> DataType('int').name
            'int'
        .
        """
        return self.raw.getName()

    def get_name(self, value):  # type: (int) -> str
        """If this data type is an enum, get the name of the value.

        :param value: the value to get the name of"""
        return self.raw.getName(value)

    def length(self):  # type: () -> int
        """Get the length of this data type in bytes

            >>> DataType('int').length()
            4
        .
        """
        return self.raw.getLength()

    __len__ = length

    @staticmethod
    def from_c(c_code, insert=True):  # type: (str, bool) -> DataType
        """Parse C structure definition and return the parsed DataType.

        If insert (true by default), add it to current program.
        Example of a valid c_code is `typedef void* HINTERNET;`

            >>> DataType.from_c('typedef void* HINTERNET;')
            HINTERNET
            >>> DataType.from_c("struct test { short a; short b; short c;};")
            pack()
            Structure test {
            0   short   2   a   ""
            2   short   2   b   ""
            4   short   2   c   ""
            }
            Length: 6 Alignment: 2

        :param c_code: the C structure definition
        :param insert: if True, add the data type to the current program
        """
        dtm = Program.current().getDataTypeManager()
        parser = CParser(dtm)

        new_dt = parser.parse(c_code)

        if insert:
            transaction = dtm.startTransaction("Adding new data")
            dtm.addDataType(new_dt, None)
            dtm.endTransaction(transaction, True)

        return new_dt


class Emulator(GhidraWrapper):
    """Wraps a Ghidra EmulatorHelper object."""

    def __init__(self):  # type: () -> None
        """Create a new Emulator object."""
        raw = EmulatorHelper(Program.current())
        GhidraWrapper.__init__(self, raw)

        # Use max_addr/2-0x8000 as stack pointer - this is 0x7fff8000 on 32-bit CPU.
        max_pointer = toAddr(0).getAddressSpace().getMaxAddress().getOffset()
        max_pointer = max_pointer % 2**64  # Java signed ints everywhere strike again.
        stack_off = ((max_pointer + 1) >> 1) - 0x8000
        self.raw.writeRegister(self.raw.getStackPointerRegister(), stack_off)

        # TODO: add a simple allocation manager
        self._hooks = {}  # type: dict[int, Callable[[Emulator], str|None]]

    def add_hook(
        self, address, hook
    ):  # type: (Addr, Callable[[Emulator], str|None]) -> None
        """Add a hook at a specified address.

        Hook is a function that gets emulator as parameter. It can return one of:

        * 'continue' or None, to continue execution normally
        * 'break' to stop execution
        * 'skip' to skip the next instruction

        Note: multiple hooks at the same address are not currently supported."""
        addr = resolve(address).getOffset()
        if addr in self._hooks:
            raise ValueError("Multiple hooks at the same address are not supported")
        self._hooks[addr] = hook

    def has_hook_at(self, address):  # type: (Addr) -> bool
        addr = resolve(address).getOffset()
        return addr in self._hooks

    def delete_hook_at(self, address):  # type: (Addr) -> None
        addr = resolve(address).getOffset()
        del self._hooks[addr]

    @property
    def pc(self):  # type: () -> int
        """Get the program counter of the emulated program."""
        return self.raw.getExecutionAddress().getOffset()

    @pc.setter
    def pc(self, address):  # type: (Addr) -> None
        """Set the program counter of the emulated program."""
        self.set_pc(address)

    def set_pc(self, address):  # type: (Addr) -> None
        """Set the program counter of the emulated program."""
        pc = self.raw.getPCRegister()
        self.raw.writeRegister(pc, resolve(address).getOffset())

    @property
    def sp_register(self):  # type: () -> str
        """Get the stack pointer register name for the emulated architecture."""
        return self.raw.getStackPointerRegister().getName()

    @property
    def sp(self):  # type: () -> int
        """Get the current stack pointer register value."""
        return self.read_register(self.sp_register)

    @sp.setter
    def sp(self, value):  # type: (Addr) -> None
        """Set the current stack pointer register value.

        :param value: new stack pointer value."""
        self.set_sp(value)

    def set_sp(self, value):  # type: (Addr) -> None
        """Set the current stack pointer register value.

        :param value: new stack pointer value."""
        self.write_register(self.sp_register, resolve(value).getOffset())

    def __getitem__(self, reg):  # type: (Reg|int) -> int
        """Read the register of the emulated program.

            >>> emulator.write_register("eax", 1337)
            >>> emulator["eax"]
            1337

        :param reg: the register or address to read from"""
        return self.read_register(reg)

    def __setitem__(self, reg, value):  # type: (Reg, int) -> None
        """Write to the register of the emulated program.

            >>> emulator["eax"] = 1234
            >>> emulator.read_register("eax")
            1337

        :param reg: the register to write to
        :param value: the value to write"""
        self.write_register(reg, value)

    def read_register(self, reg):  # type: (Reg) -> int
        """Read from the register of the emulated program.

            >>> emulator.write_register("eax", 1337)
            >>> emulator.read_register("eax")
            1337

        :param reg: the register to read from."""
        return _python_int(self.raw.readRegister(reg))

    def read_bytes(self, address, length):  # type: (Addr, int) -> bytes
        """Read `length` bytes at `address` from the emulated program.

            >>> emulator.write_bytes(0x1000, "1")
            >>> emulator.read_bytes(0x1000, 1)
            '1'

        :param address: the address to read from
        :param length: the length to read"""
        bytelist = self.raw.readMemory(resolve(address), length)
        return _bytes_from_bytelist(bytelist)

    def read_u8(self, address):  # type: (Addr) -> int
        """Read a byte from the emulated program.

            >>> emulator.write_u8(0x1000, 13)
            >>> emulator.read_u8(0x1000)
            13

        :param address: the address to read from"""
        return from_bytes(self.read_bytes(address, 1))

    def read_u16(self, address):  # type: (Addr) -> int
        """Read a 16bit unsigned integer from the emulated program.

            >>> emulator.write_u16(0x1000, 123)
            >>> emulator.read_u16(0x1000)
            123

        :param address: the address to read from"""
        return from_bytes(self.read_bytes(address, 2))

    def read_u32(self, address):  # type: (Addr) -> int
        """Read a 32bit unsigned integer from the emulated program.

            >>> emulator.write_u32(0x1000, 123)
            >>> emulator.read_u32(0x1000)
            123

        :param address: the address to read from"""
        return from_bytes(self.read_bytes(address, 4))

    def read_u64(self, address):  # type: (Addr) -> int
        """Read a 64bit unsigned integer from the emulated program.

            >>> emulator.write_u64(0x1000, 123)
            >>> emulator.read_u64(0x1000)
            123

        :param address: the address to read from"""
        return from_bytes(self.read_bytes(address, 8))

    def read_cstring(self, address):  # type: (Addr) -> str
        """Read a null-terminated string from the emulated program.

        This function reads bytes until a nullbyte is encountered.

            >>> emu.read_cstring(0x1000)
            'Hello, world!'

        :param address: address from which to start reading."""
        addr = resolve(address)
        string = ""
        while True:
            c = self.read_u8(addr)
            if c == 0:
                break
            string += chr(c)
            addr = addr.add(1)
        return string

    def read_unicode(self, address):  # type: (Addr) -> str
        """Read a null-terminated utf-16 string from the emulated program.

        This function reads bytes until a null character is encountered.

            >>> emu.read_unicode(0x1000)
            'Hello, world!'

        :param address: address from which to start reading."""
        addr = resolve(address)
        string = ""
        while True:
            c = self.read_u16(addr)
            if c == 0:
                break
            string += chr(c)
            addr = addr.add(2)
        return string

    def read_varnode(self, varnode):  # type: (Varnode) -> int
        """Read from the varnode from the emulated program.

        This method can't read hash varnodes.

            >>> fnc = Function("AddNumbers")
            >>> emu = Emulator()
            >>> emu.write_varnode(fnc.parameters[0].varnode, 2)
            >>> emu.write_varnode(fnc.parameters[1].varnode, 2)
            >>> emu.emulate(fnc.entrypoint, stop_when=lambda emu: emu.pc not in fnc.body)
            >>> emu.read_varnode(func.return_variable.varnode)
            4

        :param varnode: the varnode to read from."""
        varnode = Varnode(varnode)
        if varnode.is_constant:
            return varnode.offset
        elif varnode.is_address:
            rawnum = self.read_bytes(varnode.offset, varnode.size)
            return from_bytes(rawnum)
        elif varnode.is_unique:
            space = Program.current().getAddressFactory().getUniqueSpace()
            offset = space.getAddress(varnode.offset)
            rawnum = self.read_bytes(offset, varnode.size)
            return from_bytes(rawnum)
        elif varnode.is_stack:
            return self.raw.readStackValue(varnode.offset, varnode.size, False)
        elif varnode.is_register:
            language = Program.current().getLanguage()
            reg = language.getRegister(varnode.raw.getAddress(), varnode.size)
            return self.read_register(reg)
        raise RuntimeError("Unsupported varnode type")

    def write_register(self, reg, value):  # type: (Reg, int) -> None
        """Write to the register of the emulated program.

            >>> emulator.write_register("eax", 1)
            >>> emulator.read_register("eax")
            1

        :param reg: the register to write to
        :param value: the value to write"""
        self.raw.writeRegister(reg, value)

    def write_bytes(self, address, value):  # type: (Addr, bytes) -> None
        """Write to the memory of the emulated program.

            >>> emulator.write_bytes(0x1000, "1")
            >>> emulator.read_bytes(0x1000, 1)
            '1'

        :param address: the address to write to
        :param value: the value to write"""
        self.raw.writeMemory(resolve(address), value)

    def write_u8(self, address, value):  # type: (Addr, int) -> None
        """Write a byte to the emulated program.

            >>> emulator.write_u8(0x1000, 13)
            >>> emulator.read_u8(0x1000)
            13

        :param address: the address to write to"""
        assert 0 <= value < 2**8, "value out of range"
        self.write_bytes(address, to_bytes(value, 1))

    def write_u16(self, address, value):  # type: (Addr, int) -> None
        """Write a 16bit unsigned integer to the emulated program.

            >>> emulator.write_u16(0x1000, 13)
            >>> emulator.read_u16(0x1000)
            13

        :param address: the address to write to"""
        assert 0 <= value < 2**16, "value out of range"
        self.write_bytes(address, to_bytes(value, 2))

    def write_u32(self, address, value):  # type: (Addr, int) -> None
        """Write a 32bit unsigned integer to the emulated program.

            >>> emulator.write_u32(0x1000, 13)
            >>> emulator.read_u32(0x1000)
            13

        :param address: the address to write to"""
        assert 0 <= value < 2**32, "value out of range"
        self.write_bytes(address, to_bytes(value, 4))

    def write_u64(self, address, value):  # type: (Addr, int) -> None
        """Write a 64bit unsigned integer to the emulated program.

            >>> emulator.write_u64(0x1000, 13)
            >>> emulator.read_u64(0x1000)
            13

        :param address: the address to write to"""
        assert 0 <= value < 2**64, "value out of range"
        self.write_bytes(address, to_bytes(value, 8))

    def write_varnode(self, varnode, value):  # type: (Varnode, int) -> None
        """Set a varnode value in the emulated context.

        This method can't set hash and constant varnodes.

            >>> fnc = Function("AddNumbers")
            >>> emu = Emulator()
            >>> emu.write_varnode(fnc.parameters[0].varnode, 2)
            >>> emu.write_varnode(fnc.parameters[1].varnode, 2)
            >>> emu.emulate(fnc.entrypoint, stop_when=lambda emu: emu.pc not in fnc.body)
            >>> emu.read_varnode(func.return_variable.varnode)
            4

        :param varnode: the varnode to read from."""
        varnode = Varnode(varnode)
        if varnode.is_constant:
            raise ValueError("Can't set value of a constant varnodes")
        elif varnode.is_address:
            self.write_bytes(varnode.offset, to_bytes(value, varnode.size))
        elif varnode.is_unique:
            space = Program.current().getAddressFactory().getUniqueSpace()
            offset = space.getAddress(varnode.offset)
            self.write_bytes(offset, to_bytes(value, varnode.size))
        elif varnode.is_stack:
            self.raw.writeStackValue(varnode.offset, varnode.size, value)
        elif varnode.is_register:
            language = Program.current().getLanguage()
            reg = language.getRegister(varnode.raw.getAddress(), varnode.size)
            self.raw.writeRegister(reg, value)
        else:
            raise RuntimeError("Unsupported varnode type")

    def __run_with_hooks(self):  # type: () -> bool
        """Run the Ghidra emulator, and transparently handle all hooks.

        :return: True if emulator stopped at a breakpoint, or
          hook asked emulator to stop (by returning break)."""

        while not getMonitor().isCancelled():
            is_breakpoint = self.raw.run(getMonitor())
            if self.pc not in self._hooks:
                return is_breakpoint

            result = self._hooks[self.pc](self)
            if self.__handle_hook_result(result):
                return True

        return False

    def add_breakpoint(self, address):  # type: (Addr) -> None
        """Add a breakpoint at the given address.

        :param address: the address to break on"""
        self.raw.setBreakpoint(resolve(address))

    def clear_breakpoint(self, address):  # type: (Addr) -> None
        """Clear a breakpoint at the given address.

        :param address: the address to clear breakpoint from"""
        self.raw.clearBreakpoint(resolve(address))

    def emulate_fast(self, start, ends):  # type: (Addr, Addr|list[Addr]) -> None
        """Emulate from start to end address, using Ghidra for fast emulation.

        The main loop of this function is in Java, which makes it faster, but makes
        some features (like callbacks) impossible. This function stops on error,
        when PC reaches one of the ends, and will also call hooks.

        This method will set a breakpoint at the end address, and clear it after
        the emulation is done.

            >>> emulator.write_bytes(0x2000, "1")
            >>> emulator.emulate_fast(0x1000, 0x1005)
            >>> emulator.read_bytes(0x2000, 1)
            '0'

        :param start: the start address to emulate
        :param ends: one or many end address"""
        self.set_pc(start)

        if not isinstance(ends, (list, tuple)):
            ends = [ends]

        for end in ends:
            self.add_breakpoint(end)

        is_breakpoint = self.__run_with_hooks()

        for end in ends:
            self.clear_breakpoint(end)

        if not is_breakpoint:
            err = self.raw.getLastError()
            raise RuntimeError("Error when running: {}".format(err))

    def __handle_hook_result(self, result):  # type: (str|None) -> bool
        """Handle a hook return value and return True if emulation should stop."""
        if result is None or result == "continue":
            return False
        elif result == "skip":
            self.pc = Instruction(self.pc).next.address
            return False
        elif result == "break":
            return True
        else:
            raise RuntimeError("Invalid hook return value: {}".format(result))

    def single_step(self):  # type: () -> bool
        """Do a single emulation step. This will step into calls.

        Note: This method *will* call hooks.

        :return: True if the emulation should be stopped, False otherwise."""
        success = self.raw.step(getMonitor())
        if not success:
            err = self.raw.getLastError()
            raise RuntimeError("Error at {}: {}".format(self.pc, err))

        if self.pc in self._hooks:
            result = self._hooks[self.pc](self)
            return self.__handle_hook_result(result)
        if self.is_at_breakpoint:
            return True
        return False

    @staticmethod
    def new(
        start,
        ends=[],
        callback=lambda emu: None,
        stop_when=lambda emu: False,
        maxsteps=2**48,
    ):  # type: (Addr, Addr|list[Addr], Callable[[Emulator], str|None], Callable[[Emulator], bool], int) -> Emulator
        """Emulate from start to end address, with callback for each executed address.

            >>> Emulator.new("main", maxsteps=100)["EAX"]
            128

        This function is a convenience wrapper around emulate and can be always
        replaced by three lines of code. The above is equivalent to:

            >>> emu = Emulator()
            >>> emu.emulate("main", maxsteps=100)
            >>> emu["EAX"]
            128

        This function may be used for quickly doing one-off emulations.

        See `emulate` documentation for info about this method parameters."""
        emu = Emulator()
        emu.emulate(start, ends, callback, stop_when, maxsteps)
        return emu

    def emulate(
        self,
        start,
        ends=[],
        callback=lambda emu: None,
        stop_when=lambda emu: False,
        maxsteps=2**48,
    ):  # type: (Addr, Addr|list[Addr], Callable[[Emulator], str|None], Callable[[Emulator], bool], int) -> None
        """Emulate from start to end address, with callback for each executed address.

            >>> emu = Emulator()
            >>> def callback(emu):
            >>>     print("executing {:x}'.format(emu.pc))
            >>> emu.emulate(Function("main").entrypoint, callback=callback, maxsteps=3)
            SUB ESP,0x2d4
            PUSH EBX
            PUSH EBP

        Callback should return one of:

        * 'continue' or None, to continue execution normally
        * 'break' to stop execution
        * 'skip' to skip the next instruction
        * 'retry' like continue, but call the callback again (useful after pc change)
        * 'continue_then_break' to execute one last instruction before stopping

        Returning another value will cause an exception Callback is executed before
        stop_when condition is checked.

        This method is very flexible, but because of that it may be slower than
        pure Ghidra implementation. Consider .emulate_fast() when this method is too
        slow for you.

        :param start: the start address to emulate
        :param end: the end address to emulate
        :param callback: the callback to call before each executed instruction.
          Return one of the predefined constants here (see the docs for more info).
        :param stop_when: the callback to call before each executed instruction.
          Return True here to stop emulation.
        :param maxsteps: the maximum number of steps to execute"""
        self.set_pc(start)

        if not isinstance(ends, (list, tuple)):
            ends = [ends]
        ends = [resolve(e).getOffset() for e in ends]

        while maxsteps > 0:
            maxsteps -= 1
            if self.pc in ends:
                break

            command = callback(self)
            if command == "retry":
                continue
            elif command == "continue_then_break":
                maxsteps = 0
            elif self.__handle_hook_result(command):
                return

            if stop_when(self):
                return

            if self.single_step():
                return

    @property
    def is_at_breakpoint(self):  # type: () -> bool
        """Check if the emulator is at a breakpoint"""
        return self.raw.getEmulator().isAtBreakpoint()

    # Basic unicorn compatibility, because why not
    # You may prefer these aliases if you already know Unicorn API.
    reg_write = write_register
    reg_read = read_register
    mem_write = write_bytes
    mem_read = read_bytes
    mem_map = (
        lambda _1, _2, _3: None
    )  # This is a noop - all memory is already available.
    emu_start = lambda self, begin, until: self.emulate(begin, until)


class MemoryBlock(GhidraWrapper, BodyTrait):
    """A Ghidra wrapper for a Ghidra MemoryBlock"""

    @staticmethod
    def get(raw_or_name):  # type: (JavaObject|str|Addr) -> MemoryBlock|None
        """Gets a MemoryBlock by name or containing the given address.

        Note: for a string argument, this will try to get memoryblock by name, and
        if it fails, it will fall back to the regular behaviour of "resolve the symbol
        to the address, and get element by address

        :param raw_or_name: name or address of MemoryBlock to get
        :return: the MemoryBlock, or None if not found
        """
        memory = Program.current().getMemory()
        if isinstance(raw_or_name, str):
            raw = memory.getBlock(raw_or_name)
            if raw is not None:
                return MemoryBlock(raw)
        addr = try_resolve(raw_or_name)
        if addr is None:
            return None
        return MemoryBlock(memory.getBlock(addr))

    @staticmethod
    def all():  # type: () -> list[MemoryBlock]
        """Get all MemoryBlocks in the current program"""
        raw_blocks = Program.current().getMemory().getBlocks()
        return [MemoryBlock(raw) for raw in raw_blocks]

    @property
    def comment(self):  # type: () -> str
        """Get the comment associated with this MemoryBlock"""
        return self.raw.getComment()

    @property
    def start(self):  # type: () -> int
        """Get the first address of this MemoryBlock"""
        return self.raw.getStart().getOffset()

    @property
    def name(self):  # type: () -> str
        """Get the name of this MemoryBlock"""
        return self.raw.getName()

    address = start

    @property
    def end(self):  # type: () -> int
        return self.raw.getEnd().getOffset()

    @property
    def size(self):  # type: () -> int
        """Get the size of this MemoryBlock"""
        return int(self.raw.getSize())

    length = size

    @property
    def body(self):  # type: () -> AddressSet
        """Get the address range this instruction."""
        return AddressSet.create(self.address, self.length)

    @property
    def bytes(self):  # type: () -> bytes
        """Get the bytes of this instruction."""
        return read_bytes(self.address, self.length)


class Program(GhidraWrapper):
    """A static class that represents the current program"""

    @staticmethod
    def create_data(address, datatype):  # type: (Addr, DataT) -> None
        """Force the type of the data defined at the given address to `datatype`.

        This function will clear the old type if it already has one

        :param address: address of the data.
        :param datatype: datatype to use for the data at `address`."""
        typeobj = DataType(datatype)
        addr = resolve(address)
        try:
            createData(addr, unwrap(typeobj))
        except:
            clearListing(addr, addr.add(len(typeobj) - 1))
            createData(addr, unwrap(typeobj))

    @staticmethod
    def location():  # type: () -> int
        """Get the current location in the program.

            >>> current_location()
            0x1000

        :return: the current location in the program
        """
        return getState().getCurrentLocation().getAddress().getOffset()

    @staticmethod
    def call_graph():  # type: () -> Graph[Function]
        """Get the call graph for this program."""
        return Graph.construct(Function.all(), lambda f: f.called)

    @staticmethod
    def control_flow():  # type: () -> Graph[BasicBlock]
        """Get a graph representing the whole program control flow.

        Warning: This graph may be big, so don't try to display it."""
        return Graph.construct(BasicBlock.all(), lambda b: b.destinations)

    @staticmethod
    def basicblocks():  # type: () -> list[BasicBlock]
        """Get all the basic blocks defined in the program."""
        return BasicBlock.all()

    @staticmethod
    def memory_blocks():  # type: () -> list[MemoryBlock]
        """Get memory blocks defined for the current program."""
        return MemoryBlock.all()

    @staticmethod
    def functions():  # type: () -> list[Function]
        """Get all the functions defined in the program."""
        return Function.all()

    @staticmethod
    def instructions():  # type: () -> list[Instruction]
        """Get all the instructions defined in the program."""
        return Instruction.all()

    @staticmethod
    def body():  # type: () -> AddressSet
        """Get the set of all addresses of the program."""
        body = Program.current().getNamespaceManager().getGlobalNamespace().getBody()
        return AddressSet(body)

    @staticmethod
    def current():  # type: () -> JavaObject
        """Get the current program. Equivalent to getCurrentProgram()

        This method must be used instead of currentProgram, because the latter
        won't work well if user is using multiple programs at the same time
        (for example, many tabs in the same tool)."""
        return getCurrentProgram()

    @staticmethod
    def analyze():  # type: () -> None
        """Analyze changes. This will block when autoanalysis changes place.

        Run this when you did changes that you will need to proceed with the rest
        of the script."""
        analyzeChanges(Program.current())


class Data(GhidraWrapper):
    """ Wraps a structure for convenient access by field name """

    @staticmethod
    def get(addr):  # type: (JavaObject|str|Addr) -> Data|None
        """Return a Data instance at the given address, or None if there is
        no Data defined there."""
        if isinstance(addr, GhData):
            return Data(addr)
        addr = try_resolve(addr)
        if addr is None:
            return None
        raw = getDataAt(addr)
        if raw is None:
            return None
        return Data(raw)  # type: ignore

    def __getattr__(self, name):
        for i in range(self.raw.getNumComponents()):
            field = self.raw.getComponent(i)
            if field.getFieldName() == name:
                if field.isStructure():
                    return Data(field)
                return GhidraWrapper(field)
        raise AttributeError("Field %s does not exist" % name)


def disassemble_bytes(
    data, addr=0, max_instr=None
):  # type: (bytes, Addr, int|None) -> list[Instruction]
    """Disassemble the given bytes and return a list of Instructions.

    This function will return early if an exception during disassembly occurs.

        >>> disassemble_bytes('F')
        [INC ESI]

    Note: Address is important, because instruction meaning may depend on the location.

    :param data: the bytes to disassemble
    :param addr: the (virtual) address of the first instruction
    :param max_instr: the maximum number of instructions to disassemble, or
    to disassemble until the end of the data
    :return: a list of Instruction objects"""
    dis = PseudoDisassembler(Program.current())
    offset = 0
    result = []
    address = resolve(addr)
    if max_instr is None:
        max_instr = 100000000
    for _ in range(0, max_instr):
        try:
            arr = data[offset : offset + 16]
            rawinstr = dis.disassemble(address.add(offset), arr)
            instr = Instruction(rawinstr)
            if offset + instr.length > len(data):
                break
            result.append(instr)
            offset += instr.length
            if offset + instr.length == len(data):
                break
        except:
            break
    return result


def disassemble_at(
    address, max_instr=None, max_bytes=None
):  # type: (Addr, int|None, int|None) -> list[Instruction]
    """Disassemble the bytes from the program memory at the given address.

    If neither `max_bytes` nor `max_instr` are specified, this function will
    disassemble one instruction. If at least one of them is specified,
    this function will disassemble until one of the conditions occurs.

        >>> disassemble_at(0x0403ED0)
        [INC ESI]

    :param address: the address where to start disassembling
    :param max_bytes: maximum number of bytes to disassemble (None for no limit)
    :param max_instr: maximum number of instructions to disassemble (None for no limit)
    :return: a list of Instruction objects"""
    addr = resolve(address)

    if max_instr is None:
        _max_instr = 1 if max_bytes is None else max_bytes
    else:
        _max_instr = max_instr

    if max_bytes is None:
        to_block_end = MemoryBlock(addr).end - addr.getOffset()
        # Hacky and inefficient, but good enough for now (and correct)
        _max_bytes = min(to_block_end, _max_instr * 16)
    else:
        _max_bytes = max_bytes
    data = read_bytes(addr, _max_bytes)

    return disassemble_bytes(data, addr, _max_instr)


def assemble_at(
    address, instructions, pad_to=0
):  # type: (Addr, str|list[str], int) -> list[Instruction]
    """Assemble the given instructions and write them at the given address.

    Note: Ghidra is a bit picky, and case-sensitive when it comes to opcodes.
    For example, use "MOV EAX, EBX" instead of "mov eax, ebx".

        >>> assemble_at(Function("exit").entrypoint, "RET")

    :param address: the address where to write the instructions
    :param instructions: a list of instructions, or a single instruction to assemble
    :param pad_to: optionally, pad the code with NOPs to reach this size
    :return: the newly assembled instructions"""
    # Note: Assembler API is actually quite user-friendly and doesn't require
    # wrapping. But let's wrap it for consistency.
    addr = resolve(address)
    asm = Assemblers.getAssembler(Program.current())
    result = [Instruction(i) for i in asm.assemble(addr, instructions)]

    # Append NOPs at the end, if length is shorter than pad_to.
    # This is purely to make the assembled code look nicer.
    if result:
        last = result[-1]
        end_addr = last.address + last.length
        code_size = end_addr - addr.getOffset()
        if pad_to > code_size:
            asm.assemble(addr.add(code_size), ["NOP"] * (pad_to - code_size))

    # Do what Ghidra should do automaticaly, and automatically try to disassemble
    # jump targets from the newly assembled instructions
    for instr in result:
        for xref in instr.xrefs_from:
            if xref.is_call or xref.is_jump:
                disassemble(toAddr(xref.to_address))

    return result


def assemble_to_bytes(instructions, address=0):  # type: (str|list[str], Addr) -> bytes
    """Assemble the given instructions and return them as an array of bytes.

    Note: Ghidra is a bit picky, and case-sensitive when it comes to opcodes.
    For example, use "MOV EAX, EBX" instead of "mov eax, ebx".

    Note: Address is important, because instruction bytes may depend on the location.

        >>> assemble_to_bytes("ADD EAX, EAX")
        "\x01\xc0"
        >>> assemble_to_bytes(["ADD EAX, EAX", "ADD EAX, EAX"])
        "\x01\xc0\x01\xc0"

    :param address: the address to use as a base for instructions
    :param instructions: a list of instructions, or a single instruction to assemble"""
    # Note: Assembler API is actually quite user-friendly and doesn't require
    # wrapping. But let's wrap it for consistency.
    addr_obj = resolve(address)
    asm = Assemblers.getAssembler(Program.current())
    if isinstance(instructions, Str):
        return _bytes_from_bytelist(asm.assembleLine(addr_obj, instructions))
    result = _asbytes("")
    for instr in instructions:
        result += _bytes_from_bytelist(
            asm.assembleLine(addr_obj.add(len(result)), instr)
        )
    return result


def assemble(
    instructions, address=0
):  # type: (str|list[str], Addr) -> list[Instruction]
    """Assemble the given instructions and return them as a list of instructions.

    Note: Address is important, because instruction meaning may depend on the location.

    :param address: the address where the instructious would be written
    :param instructions: a list of instructions, or a single instruction to assemble
    :return: the newly assembled instructions"""
    data = assemble_to_bytes(instructions, address)
    return disassemble_bytes(data, address)


def get_string(address):  # type: (Addr) -> str|None
    """Get the string defined at the given address.

    This function will return None if the data defined in Ghidra at the
    given address is not a string. This function will also return None
    if the string at `adress` was not defined in Ghidra. To read a
    null-terminated string from Ghidra memory, use `read_cstring` instead.

        >>> get_string(0x1000)
        'Hello, world!'

    :param address: address where string should be located."""
    string = getDataAt(resolve(address))
    if string and string.hasStringValue():
        return string.getValue()
    return None


def read_cstring(address):  # type: (Addr) -> str
    """Read a null-terminated string from Ghidra memory.

    This function ignores metadata available to Ghidra and just reads
    the bytes until a nullbyte is encountered.

        >>> read_cstring(0x1000)
        'Hello, world!'

    :param address: address from which to start reading."""
    addr = resolve(address)
    string = ""
    while True:
        c = read_u8(addr)
        if c == 0:
            break
        string += chr(c)
        addr = addr.add(1)
    return string


def read_unicode(address):  # type: (Addr) -> str
    """Read a null-terminated utf-16 string from Ghidra memory.

    This function ignores metadata available to Ghidra and just reads
    the bytes until a null character is encountered.

        >>> read_unicode(0x1000)
        'Hello, world!'

    :param address: address from which to start reading."""
    addr = resolve(address)
    string = ""
    while True:
        c = read_u16(addr)
        if c == 0:
            break
        string += chr(c)
        addr = addr.add(2)
    return string


def read_u8(address):  # type: (Addr) -> int
    """Read a byte from program at address.

        >>> read_u8(0x1000)
        0x01

    :param address: address from which to read."""
    return from_bytes(read_bytes(address, 1))


def read_u16(address):  # type: (Addr) -> int
    """Read a 16bit integer from program at address.

        >>> read_u16(0x1000)
        0x0102

    :param address: address from which to read."""
    return from_bytes(read_bytes(address, 2))


def read_u32(address):  # type: (Addr) -> int
    """Read a 32bit integer from program at address.

        >>> read_u32(0x1000)
        0x01020304

    :param address: address from which to read."""
    return from_bytes(read_bytes(address, 4))


def read_u64(address):  # type: (Addr) -> int
    """Read a 64bit integer from program at address.

        >>> read_u32(0x1000)
        0x0102030405060708

    :param address: address from which to read."""
    return from_bytes(read_bytes(address, 8))


def read_bytes(address, length):  # type: (Addr, int) -> bytes
    """Read a byte stream from program at address.

        >>> read_bytes(0x1000, 4)
        'test'

    :param address: address from which to read.
    :param length: number of bytes to read."""
    address = resolve(address)
    return _bytes_from_bytelist(getBytes(address, length))


def from_bytes(b):  # type: (bytes) -> int
    """Decode a bytes as a little-endian integer.

        >>> from_bytes('ab')
        25185

    :param b: byte stream to decode."""
    bl = _bytes_as_list(b)
    return sum(v << (i * 8) for i, v in enumerate(bl))


def to_bytes(value, length):  # type: (int, int) -> bytes
    """Encode an integer as a little-endian byte stream.

        >>> to_bytes(0x0102, 2)
        '\\x01\\x02'

    :param value: integer to encode.
    :param length: number of bytes of the result."""
    out = ""
    for i in range(length):
        out += chr(value & 0xFF)
        value >>= 8
    return _asbytes(out)


def write_bytes(address, data):  # type: (Addr, bytes) -> None
    """Write the provided bytes at a given address.

        >>> write_bytes(0x1000, "test)
        >>> read_bytes(0x1000, 4)
        'test'

    :param address: address where bytes should be written.
    :param data: bytes to write."""
    addr = resolve(address)
    try:
        setBytes(addr, data)
    except:
        clearListing(addr, addr.add(len(data) - 1))
        setBytes(addr, data)


def unhex(s):  # type: (str) -> bytes
    """Decode a hex string.

        >>> unhex("01 02")
        '0102'

    :param s: hex string to decode."""
    return _unhex(s)


def enhex(s):  # type: (bytes | list[int]) -> str
    """Convert raw bytes to a hex string.

        >>> enhex([0x01, 0x02])
        '0102'

    :param s: raw bytes to encode."""
    if not isinstance(s, Str):
        return _enhex(_asbytes("".join(chr(c) for c in s)))
    return _enhex(s)


def xor(a, b):  # type: (bytes, bytes) -> bytes
    """XOR two bytestrings together.

    If two bytestrings are not the same length, the result will be
    truncated to the length of the shorter string.

        >>> xor("\\x01\\x02", "\\x03\\x04")
        '\\x02\\x06'

    :param a: the first bytestring.
    :param b: the second bytestring."""
    al = _bytes_as_list(a)
    bl = _bytes_as_list(b)
    return _asbytes("".join(chr(x ^ y) for x, y in zip(al, bl)))


def _get_unique_string(obj):  # type: (object) -> str
    """Get a unique string for a given object.

    This function is used to convert objects to strings for the graph.
    The only requirement is that the returned string is unique for
    each object. Function will just return str(obj) for primitives,
    and for the rest it will try to return str(obj.address).

    Warning: This function is an implementation detail, and may be changed often.

    :param obj: the object to convert."""
    if isinstance(obj, unicode):
        # This can only happen for Jython - in this case, convert unicode to str.
        return obj.encode()
    elif isinstance(obj, str):
        return obj
    elif isinstance(obj, (int, long)):
        return str(obj)
    elif isinstance(obj, PcodeOp):
        return str(obj.raw.getSeqnum())
    elif isinstance(obj, Varnode):
        return str(obj.raw)
    elif hasattr(obj, "address"):
        # So you can define your own way to convert an object to a string.
        return str(obj.address)  # type: ignore
    else:
        raise TypeError("Cannot convert object {} to string".format(obj))


def _pattern_to_bytes(pattern):  # type: (str) -> bytes
    """Convert a pattern string to a byte string.

        >>> _pattern_to_bytes("01 02 ?? 04")
        '\\x01\\x02\\x00\\x04'

    :param pattern: the pattern string."""
    pattern = pattern.replace("?", "0")
    return unhex(pattern)


def _pattern_to_mask(pattern):  # type: (str) -> bytes
    """Convert a pattern string to a mask string.

        >>> _pattern_to_mask("01 02 ?? 04")
        '\\xff\\xff\\x00\\xff'

    :param pattern: the pattern string."""
    pattern = pattern.replace(" ", "").replace("\n", "")
    return unhex("".join("0" if c == "?" else "f" for c in pattern))


def findone_pattern(byte_pattern, start=0):  # type: (str, Addr) -> int|None
    """Find the first occurrence of a byte pattern in the program (or None).

        >>> findone_pattern("01 02 ?? 04")
        0x1000

    :param byte_pattern: the pattern string.
    :param start: the address to start searching from.
    :return: address of the first occurrence, or None if not found."""
    start = resolve(start)
    bytes = _pattern_to_bytes(byte_pattern)
    mask = _pattern_to_mask(byte_pattern)
    addr = (
        Program.current().getMemory().findBytes(start, bytes, mask, True, getMonitor())
    )
    if not addr:
        return None
    return addr.getOffset()


def findall_pattern(byte_pattern):  # type: (str) -> Iterator[int]
    """Find all occurrences of a byte pattern in the program.

        >>> findall_pattern("01 02 ?? 04")
        [0x1000, 0x1004]

    :param byte_pattern: the pattern string.
    :return: iterator over all addresses of all occurrences."""
    addr = -1
    while True:
        addr = findone_pattern(byte_pattern, start=addr + 1)
        if addr is None:
            break
        yield addr

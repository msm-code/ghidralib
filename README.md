# ghidralib

![](./dragon1.png)

This library is an attempt to provide a Pythonic standard library for Ghidra.

The main goal is to make writing quick&dirty scripts actually quick, and not that dirty.

## Installation

Just copy the ghidralib.py file to your Ghidra scripts directory.

## Usage

**This is a work in progress. API is not stable. Expect changes.**

Proper documentation is coming, so for now I'll just showcase a few features:

1. Process all calls to a function and get the parameters:

```python
for call in Function("MyCustomCrypto").calls:
    ctx = call.emulate()
    key, data = ctx.read_register("eax"), ctx.read_register("edx")
    if key and data:
        datalen = get_u32(data - 4)
        print(call.address, decode(get_bytes(data, datalen)))
```

2. Even simpler (but slow) version:

```python
for call in Function("MyCustomCrypto").calls:
    key, data = call.get_args()
    if key and data:
        datalen = get_u32(data - 4)
        print(call.address, decode(get_bytes(data, datalen)))
```

3. Get function instructions:

```python
print(Function("main").instructions)
```

For comparison, plain Ghidra's equivalent:

```python
function_manager = currentProgram.getFunctionManager()
symbol_table = currentProgram.getSymbolTable()
main = list(symbol_table.getSymbols('main'))[0].getAddress()
function = function_manager.getFunctionAt(main)
instructions = currentProgram.getListing().getInstructions(function.getBody(), True)
print(list(instructions))
```

Or let's say you have a string structure `uint8_t *data; uint32_t len;` at 0x1000 and you want to read it:

```python
pos, len_bytes = get_u32(0x10000), get_u32(0x10000 + 4)
print(get_bytes(pos, len_bytes))
```

Plain Ghidra equivalent:

```python
start_address = toAddr(0x10000)
pos = currentProgram.getMemory().getInt(start_address)
len_bytes = currentProgram.getMemory().getInt(start_address.add(4))
data = getBytes(toAddr(pos), len_bytes)
print(" ".join(chr(c % 256) for byte in data))  # signed bytes <3
```

4. Tons more QoL features:

```python
DataType("_NT_TIB")  # Get a datatype by name
DataType.from_c("typedef void* HINTERNET;")  # Quickly parse structs and typedefs
Symbol("main")  # Get a symbol by name
Symbol(0x8ca39c)  # You can also create symbol by address (as integer or Ghidra object)
print(Function(0x8ca3f0).decompile())  # Decompile a function containing address
print(Instruction(0x8ca3f0).pcode)  # Get low pcode (fast)
print(Instruction(0x8ca3f0).high_pcode)  # Get high pcode (slow)
BasicBlock(0x123456)  # Get a basic block containing address
# And much more
```

5. Last but not least, everything has type hints (using Jython compatible type comments).
It makes programming in Python *much* easier if your IDE supports that.

6. You can always retreat to familiar Ghidra types - just access the `.raw` property.
For example `instruction.raw` is a Ghidra Instruction object, similarly `function.raw` is a Ghidra Function.

More examples coming soon.

## Contributing

A bit too early to ask for contributions, but PRs very welcome.
Ghidra API sufrace is huge and I covered just a small part of it (that I use most often).
Feel free to open PRs to add things you are missing.

*Dragon icon at the top created by cube29, flaticon*

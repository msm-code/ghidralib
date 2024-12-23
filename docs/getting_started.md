# Getting Started

This document contains an introduction to the most important objects
wrapped by this library, and a few more motivational segments.

* [Main Actors](#main-actors) - description of the most important
ghidralib objects
* [Working at various abstraction levels](#working-at-various-abstraction-levels)
description of the various abstraction levels wrapped (and made easy!)
by ghidralib.
* [Conventions](#conventions) this library follows some design rules.
They are hopefully intuitive, but understanding them may make your
first steps easier.
* [IDE configuration](#ide-configuration) I strongly recommend using
an IDE that supports type-checking.

## Installation

To use ghidralib, **just drop [this file](https://github.com/msm-code/ghidralib/blob/master/ghidralib.py) into your ghidra_scripts directory**.
Click [here](https://raw.githubusercontent.com/msm-code/ghidralib/refs/heads/master/ghidralib.py)
for a direct download link.

## Main actors

### Function

Check these usage examples:

```python
from ghidralib import *
# Get a function at address 0x8ca3f0
Function(0x8ca3f0)

# Get a function named "main"
Function("main")

# Print all assembly instructions in main function
for instr in Function("main").instructions:
    print(instr)

# Print all pcode instructions in main function
for instr in Function("main").pcode:
    print(instr)

# Print all high-level pcode instructions in main function
# Or you can do it in 100 lines of Java:
# https://github.com/evm-sec/high-pcode/blob/main/HighPCode.java
for instr in Function("main").high_pcode:
    print(instr)

# Print all basic blocks in main function
for block in Function("main").basicblocks:
    print(block)

# Decompile the main function and print the C code.
print(Function("main").decompile())

# Define a function at address 0x400300
Function.create(0x400300, "main")

# Print a value of eax and edx at each call of this function
for call in Function("MyCustomCrypto").calls:
    ctx = call.emulate()
    key, data = ctx.read_register("eax"), ctx.read_register("edx")
    print(key, data)

# Print parameters of each call to this function, as seen by
# the decompiler
for call in Function("MyCustomCrypto").calls:
    key, data = call.get_args()
    print(key, data)
```

Read more in the [`Function` object documentation](reference.md#ghidralib.Function).

### Instruction

Check these usage examples:

```python
# Get an instruction at address 0x8ca3f0
Instruction(0x8ca3f0)

# Get the first instruction in main function
Instruction("main")

# Print the instruction mnemonic and operands
instr = Instruction(0x8ca3f0)
print(instr.mnemonic, instr.operands)

# Print the instruction pcode:
for op in instr.pcode:
    print(op)

# Print the instruction high-level pcode:
for op in instr.high_pcode:
    print(op)
```

Read more in the [`Instruction` object documentation](reference.md#ghidralib.Instruction).

### BasicBlock

Check these usage examples:

```python
# TODO: DFS example
```

Read more in the [`BasicBlock` object documentation](reference.md#ghidralib.BasicBlock).

### DataType

Check these usage examples:

```python
# Get a datatype called "int"
DataType("int")

# Parse a datatype from C string
HINTERNET = DataType.from_c('typedef void* HINTERNET;')

# Change a datatype at location
create_data(0x1234, HINTERNET)
```

Read more in the [`DataType` object documentation](reference.md#ghidralib.DataType).

### Symbol

Sometimes called a label. Check these usage examples:

```python
# Get a symbol (label) at address 0x8ca3f0
Symbol(0x8ca3f0)

# Get a symbol (label) named "main"
Symbol("main")

# Create a label "foo" at address 0x1234
Symbol.create(0x1234, "foo")

# Change the symbol's data type
Symbol("DAT_1234").set_type(HINTERNET)

# Print all symbols in the program
for symbol in Symbol.all():
    print(symbol)

# Rename all unknown data to something funniner
for symbol in Symbol.all():
    if symbol.name.startswith("DAT_"):
        symbol.rename(f"funniner_{symbol.name}")
```

Read more in the [`Symbol` object documentation](reference.md#ghidralib.Symbol).

## Working at various abstraction levels

TODO

* **Assembly instructions**
* **Pcode instructions**
* **High Pcode instructions**
* **Pcode AST graph**
* **Clang tokens**

## Conventions

There are a few conventions that this library follows, and which may be useful
when learning:

* Every object that wraps a Ghidra object has a `.raw` property that can be used
  to get the unwrapped object. So you can always "escape" ghidralib:

```python
Function("main").raw.UNKNOWN_STACK_DEPTH_CHANGE
2147483647
```

* Objects that have an address can be addressed in many different ways - by name,
  by address, or by Ghidra address object. All of these are equivalent:

```python
Function("main")
Function(0x669d1e)
Function(toAddr(0x669d1e))
```

* Additionaly, wrappers are "tolerant" and try to drop unnecessary layers.
  All of these are resolved to the same object:

```python
Instruction(getInstructionAt(toAddr(0x0669d2a)))  # from raw object
Instruction(0x669d2a)  # from integer
Instruction(Instruction(0x669d2a))  # wrapped two times
```

* Same goes in the other direction btw - Java API will accept wrappers

```python
getInstructionBefore(getInstructionAt(toAddr(0x0669d2a)))  # pure java
getInstructionBefore(Instruction(0x0669d2a))  # mixup library object
```

* Many objects expose a static constructor methods, where it makes sense.
  Possible methods are "get", "create", "all", "create". So for example
  instead of `getAllSymbols()` use `Symbols.all()`.

* The difference between `Function.get(addr)` and `Function(addr)` is that
  `Function.get` returns `None` instead of raising an exception when
  the desired object was not found.

## IDE Configuration

I strongly recommend using an IDE that supports type-checking. This is why:

![](typecheck.png)

I personally use is VS Code with Python extensions. If you install
VsCode/VsCodium, a Python extension, and just drop ghidralib.py
in the ghidra_scripts directory, then everything should "just work".

If for some reason your script lives in a different directory than
ghidralib, override the PYTHONPATH so the typechecker knows how to
import it:

```json
{
    "python.analysis.extraPaths": ["/home/you/Projects/ghidralib"],
    "terminal.integrated.env.windows": {
        "PYTHONPATH": "/home/you/Projects/ghidralib",
    }
}
```

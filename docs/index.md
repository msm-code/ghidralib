# Index

## Welcome to ghidralib documentation!

This library is an attempt to provide a Pythonic standard library for Ghidra.

The Ghidra scripting API, while extremely powerful, is not well suited for writing
quick one-off scripts when reverse-engineering something at 3AM. Scripts usually
end up verbose, fragile (no static type-checking) and with camelCaseEverywhere.

The goal of this library is to make scripting easier and... fun.

```python
for block in Function("main").basicblocks:
    for instr in block.instructions:
        for pcode in instr.pcode:
            args = ", ".join(map(str, pcode.inputs_simple))
            print("{:x} {} {}".format(pcode.address, pcode.mnemonic, args))
```

## Basic Usage

This section contains a few small snippets to get you started. For actually useful
examples, check out the
[examples directory](https://github.com/msm-code/ghidralib/tree/master/examples)
on Github. For more in-depth explanation of the API, check out the
[program model](./program_model.md) section.

## General conventions

There are a few conventions that this library follows, and which may be useful
when orienting yourself in it:

1. Every object that wraps a Ghidra object has a `.raw` property that can be used
  to get the unwrapped object. So you can always "escape" ghidralib:

```python
>>> Function("main").raw.UNKNOWN_STACK_DEPTH_CHANGE
2147483647
```

2. Objects that have an address can be addressed in many different ways - by name,
  by address, or by Ghidra address object. All of these are equivalent:

```python
Function("main")
Function(0x669d1e)
Function(toAddr(0x669d1e))
```

3. Additionaly, wrappers are "tolerant" and try to drop unnecessary layers.
  All of these are resolved to the same object:

```python
Instruction(getInstructionAt(toAddr(0x0669d2a)))  # from raw object
Instruction(0x669d2a)  # from integer
Instruction(Instruction(0x669d2a))  # wrapped two times
```

4. Same goes in the other direction btw - Java API will accept wrappers

```python
getInstructionBefore(getInstructionAt(toAddr(0x0669d2a)))  # pure java
getInstructionBefore(Instruction(0x0669d2a))  # mixup library object
```

5. Many objects expose a static constructor methods, where it makes sense.
  Possible methods are "get", "create", "all", "create". So for example
  instead of `getAllSymbols()` use `Symbols.all()`.

  The difference between `Function.get(addr)` and `Function(addr)` is that
  `Function.get` returns `None` instead of raising an exception when
  the desired object was not found.

# Emulator

Ghidra features a powerful PCode emulator, which can be used to emulate whole
functions or pieces of code.

Ghidralib wraps this emulator with a class called `Emulator`. The basic usage is
as follows:

```python
emu = Emulator()
emu.emulate(0x400000, 0x400010)
print(emu["eax"])
```

### Basics

Looks easy enough, now let's try it in practice. Create and compile a following C
program:

```c
#include <stdio.h>
#include <stdlib.h>

int hash(int value) {
    return (value * 10) + (value ^ 7);
}

void check(int value) {
    if (hash(value) == 189) {
        printf("Success!");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) { return 1; }
    check(atoi(argv[1]));
    return 0;
}
```

Compile it with `gcc -O0 test.c -o test`. Make sure to disable optimisation with
`-O0`, so the functions are not optimized out. Now load this program to Ghidra,
and open interactive console. And check that everything is in order:

```python
>>> from ghidralib import *
>>> print(hex(Function("main").address))
0x401190
>>> print(hex(Function("check").address))
0x401159
>>> print(hex(Function("hash").address))
0x401136
```

Now the main point, let's try the Emulator. We may want to emulate the `hash` function
to check how it behaves. For emulation we need a start and end address. You can copy
it from the listing view, but for the demonstration I will print that with python too:

```python
hash_function = Function("hash")
>>> for instr in hash_function.instructions:
...    print("0x{:x} {}".format(instr.address, instr))
... 
0x401136 PUSH RBP
0x401137 MOV RBP,RSP
0x40113a MOV dword ptr [RBP + -0x4],EDI
0x40113d MOV EDX,dword ptr [RBP + -0x4]
0x401140 MOV EAX,EDX
0x401142 SHL EAX,0x2
0x401145 ADD EAX,EDX
0x401147 ADD EAX,EAX
0x401149 MOV EDX,EAX
0x40114b MOV EAX,dword ptr [RBP + -0x4]
0x40114e XOR EAX,0x7
0x401151 ADD EAX,EDX
0x401153 POP RBP
0x401154 XOR EDX,EDX
0x401156 XOR EDI,EDI
0x401158 RET
```

**Note**: we assume Linux x64 ABI everywhere. If you're on Windows or another
architecture, you'll need to adjust the code (especially register names).

So we want to emulate between 0x401136 and 0x401158, and the parameter is in EDI.

```python
>>> emu = Emulator()
>>> emu["RDI"] = 10  # We asume Linux x64 ABI
>>> emu.emulate(0x401136, 0x401158)
>>> print(emu["RAX"])
113
```

Great, we successfully emulated our first function. Instead of using hardcoded
addresses, it's usually easier to use object attributes. This is equivalent:

```python
>>> emu = Emulator()
>>> emu["RDI"] = 10
>>> emu.emulate(hash_function.address, hash_function.exitpoints)
>>> print(emu["RAX"])
113
```

Function.exitpoints is a list that contains all function exit points - perfect
for our use-case here.

By the way, instead of indexing like `emu["EAX"]` you can use `emu.read_register`
and `emu.write_register`. Consider using the more verbose format when writing
reusable scripts, but `emu["EAX"]` is faster to type when working interactively.

### Hooks

Often we are interested in the details of the execution, and we want to
process every instruction in some way. We can easily do this using the `callback` parameter:

```python
>>> emu = Emulator()
>>> def print_callback(emu):
...     instr = Instruction(emu.pc)
...     print("executing 0x{:x} {}".format(emu.pc, instr))

>>> emu.emulate(hash_function.address, hash_function.exitpoints, callback=print_callback)
executing 0x401136 PUSH RBP
executing 0x401137 MOV RBP,RSP
executing 0x40113a MOV dword ptr [RBP + -0x4],EDI
executing 0x40113d MOV EDX,dword ptr [RBP + -0x4]
executing 0x401140 MOV EAX,EDX
executing 0x401142 SHL EAX,0x2
executing 0x401145 ADD EAX,EDX
executing 0x401147 ADD EAX,EAX
executing 0x401149 MOV EDX,EAX
executing 0x40114b MOV EAX,dword ptr [RBP + -0x4]
executing 0x40114e XOR EAX,0x7
executing 0x401151 ADD EAX,EDX
executing 0x401153 POP RBP
executing 0x401154 XOR EDX,EDX
executing 0x401156 XOR EDI,EDI
```

You can change the emulator context in the hook, and you can control the execution
using the callback return value. In particular, you can return:

* `continue` to continue execution normally (this is the default)
* `break` to stop execution immediately
* `continue_then_break` to stop execution after executing the current instruction
* `skip` to skip the current instruction and execute the one immediately after it
* `retry` means that emulator should try to execute the same instruction again.
    This is only useful if you changed PC in the callback and want to reevaluate it.

So for example, instead of providing the return address directly you can
execute until the `ret` instruction:

```python
>>> emu = Emulator()
>>> def execute_until_ret(emu):
...     instr = Instruction(emu.pc)
...     if instr.mnemonic == "RET":
...         return "break"
...     return "continue"

>>> emu["RDI"] = 10
>>> emu.emulate(hash_function.address, callback=execute_until_ret)
>>> print(emu["RAX"])
113
```

By the way, as a reminder, you can use a symbol name almost everywhere instead of
an address. For example, `hash_function.address` is equivalent to "hash" and you
can as well do

```python
>>> emu.emulate("hash", callback=execute_until_ret)
```

This is probably not a good idea in serious scripts, but it's a nice trick for
quick hacks.

**Exercise**: Use your knowledge of the emulator to find a value that will make the
`hash` function return 189. Hint: emulate `hash` in a for loop and check the return value.

### Hooks and external functions

Another thing we can do with hooks is dealing with `calls`. For example, `check`
function looks like this:

```python
>>> for instr in Function("check").instructions:
...     print("0x{:x} {}".format(instr.address, instr))
... 
0x401159 PUSH RBP
0x40115a MOV RBP,RSP
0x40115d SUB RSP,0x10
0x401161 MOV dword ptr [RBP + -0x4],EDI
0x401164 MOV EAX,dword ptr [RBP + -0x4]
0x401167 MOV EDI,EAX
0x401169 CALL 0x00401136
0x40116e CMP EAX,0xbd
0x401173 JNZ 0x00401189
0x401175 LEA RAX,[0x402004]
0x40117c MOV RDI,RAX
0x40117f MOV EAX,0x0
0x401184 CALL 0x00401030
0x401189 NOP
0x40118a LEAVE
0x40118b XOR EAX,EAX
0x40118d XOR EDI,EDI
0x40118f RET
```

The first call is to `hash` function, but the second one is to `printf`. We can't easily
emulate this function, because it's outside of the current program. To avoid crashing
the emulation, we can use the hook to skip the calls:

```python
>>> check_function = Function("check")
>>> def skip_calls(emu):
...     instr = Instruction(emu.pc)
...     if instr.mnemonic == "CALL":
...         return "skip"
...     return "continue"
```

But let's do something else: let's emulate `check` function until the `CALL hash` instruction,
but skip the call and just return `189` directly. Then emulate until the `CALL printf` instruction,
and print the parameter passed to `printf`. The callback gets more complicated now:

```python
>>> def emulate_check(emu):
...     instr = Instruction(emu.pc)
...     if instr.address == 0x401169:
...         emu["RAX"] = 189
...         return "skip"
...     if instr.address == 0x401184:
...         string_addr = emu["RDI"]  # cstring parameter is in RDI (linux ABI)
...         print(emu.read_cstring(string_addr))
...         return "break"

>>> check_function = Function("check")
>>> emu = Emulator()
>>> emu.emulate(check_function.address, callback=emulate_check)
Success!
```

We successfully "tricked" the check function into executing the "success"
branch and trying to print the `Success!` string.

But this code is not very nice. We can use emulator hooks to make it clearer.
Hooks are pieces of code that can be automatically executed at certain points
during emulation. You can register a hook for a specific address:

```python
def printf_hook(emu):
    arg = emu.read_cstring(emu["RDI"])
    print("printf called with '{}'".format(arg))
    return "break"

def hash_hook(emu):
    emu["RAX"] = 189
    emu.pc = emu.read_u64(emu.sp)
    emu.sp += 8

emu = Emulator()
emu.add_hook("printf", printf_hook)
emu.add_hook("hash", hash_hook)
emu.emulate("check")
```

Note that we again (ab)use automatic symbol resolution here. The last three lines
are equivalent to:

```python
emu.add_hook(Symbol("printf").address, printf_hook)
emu.add_hook(Symbol("hash").address, hash_hook)
emu.emulate(Symbol("check").address)
```

**Exercise**: Create a hook for `atoi` function that will simulate the libc function -
it should parse the string from the parameter and return it in RAX. Test it by emulating
the "call atoi" instruction with a string parameter.

### State inspection

Of course, after emulation we are interested in the final state of the emulator.
We already showcased reading and writing registers, and we used `read_cstring` function
in the hook. There are also other useful functions:

* `emu.read_register(reg)` and `emu.write_register(reg, val)` - read or write a register
* `emu[reg]` and `emu[reg] = val` - read or write a register, short version
* `emu.read_u64(addr)` and `emu.write_u64(addr, val)` - read or write a 64-bit value at a given address
* `emu.read_u32(addr)` and `emu.write_u32(addr, val)` - read or write a 32-bit value at a given address
* `emu.read_u16(addr)` and `emu.write_u16(addr, val)` - read or write a 16-bit value at a given address
* `emu.read_u8(addr)` and `emu.write_u8(addr, val)` - read or write an 8-bit value at a given address
* `emu.read_bytes(addr, size)` - read `size` bytes from `addr`
* `emu.write_bytes(addr, bytes)` - write the given `bytes` to `addr`
* `emu.read_cstring(addr)` - read bytes starting from `addr` until a null byte is found.
* `emu.read_unicode(addr)` - read 16bit chars starting from `addr` until a null character is found.
* `emu.read_varnode` and `emu.write_varnode` - read or write a varnode

They should all be self-explanatory, except the last one. Varnodes are a Ghidra term for an
almost arbitrary value. In particular, Function signature contains information about how variables and
parameters map to varnodes:

```python
>>> Function("hash").return_variable
[int <RETURN>@EAX:4]
>>> Function("hash").return_variable.varnode
(register, 0x0, 4)
>>> Function("hash").parameters
[[uint param_1@EDI:4]]
>>> Function("hash").parameters[0].varnode
(register, 0x38, 4)
```

You can use `read_varnode` and `write_varnode` to manipulate these values in a pretty generic way.
For example, this is levaraged by `Function.emulate`, to emulate functions in a very generic way:

```python
>>> Function("hash").emulate_simple(10)
113
```

It doesn't get any easier than that. The `simple` in the name refers to the return value -
in many cases you will want to use `Function.emulate` to get the whole context of the
emulator after execution.

**Exercise**: Complete the `atoi` hook from the previous exercise first. Then create an emulator,
add `printf` and `atoi` hooks, and execute a `main` function with the correct parameters.
This will require you to pass correct `argc` and `argv` parameters.

### Misc features

**maxsteps**

When you emulate a function, you may want to limit the number of steps it can take:

```python
>>> emu = Emulator()
>>> def callback(emu):
>>>     print("executing {:x}'.format(emu.pc))
>>> emu.trace(Function("main").entrypoint, callback=callback, maxsteps=3)
SUB ESP,0x2d4
PUSH EBX
PUSH EBP
```

Especially if you're emulatingh random pieces of code, setting maxsteps
to something reasonable (like 2000 instructions) may save you from accidentaly
executing an infinite loops.

**Breakpoints**

You can set and remove breakpoints using `add_breakpoint` and `clear_breakpoint`
methods

**emulate_fast**

Ghidra emulator is not very fast, but ghidralib `emulate` is even slower - because
we support callbacks, we need to go back and forth between Python and Java.

To make things faster, you can use the `emulate_fast` function. It keeps the
main loop of the emulation in Java, which may matter in some cases.
The downside is that it doesn't support callbacks or instruction counting -
you can only emulate until a specific address. As an upside, function hooks
are supprted.

**Emulation shorthands**

To save precious keystrokes you may combine creating an emulator, running it,
and inspecting the result into one step with:

```python
>>> Emulator.new("main", maxsteps=100)["EAX"]
128
```

This convenience wrapper is equivalent to the following code:

```python
>>> emu = Emulator()
>>> emu.emulate("main", maxsteps=100)
>>> emu["EAX"]
128
```

Some other objects also provide helpers to do the obvious thing with emulator.
For example, you can emulate a function call with:


```python
>>> emu = Function("test").emulate(10)
>>> emu["EAX"]
113
>>> # Or an even shorter version
>>> Function("test").emulate_simple(10)
113
```

**Unicorn compatibility**

There is a very, very thin compatibility layer with Unicorn. There are aliases
provided for the following Unicorn methods: `reg_write`, `reg_read`, `mem_write`,
`mem_read`, `mem_map`, `emu_start`. Why? The idea is that many people already
know Unicorn. It may make it a tiny bit easier for them if they can use familiar
method names instead of learning a completely new set.

The goal is not to provide actual compatibility layer - Unicorn is a very different
library and `ghidralib` won't replace it. The only goal is really so Unicorn users
can use familiar names if they forget ghidralib equivalents. If you are not
an Unicorn user, don't use them.


### Learn more

Check out relevant examples in the `examples` directory, especially:

* [EmulatorHooks.py](https://github.com/msm-code/ghidralib/blob/master/examples/EmulatorHooks.py)
* [ContextRecovery.py](https://github.com/msm-code/ghidralib/blob/master/examples/ContextRecovery.py)
* [LummaPatternBasedDeobfuscation.py](https://github.com/msm-code/ghidralib/blob/master/examples/LummaPatternBasedDeobfuscation.py)

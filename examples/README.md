# Examples

Some examples of how to use the library in practice (a lot of this is code
I wrote during my work as a reverse-engineer).

This code will be also used for unit-tests in the future (I hope).

## Boring

Not everything in life is interesting. Scripts here are mostly rewritten Ghidra
examples, or very small deobfuscation scripts.

* [SwitchOverride]: Fixup a switch statement at the pointer location.

## Everyday use

* [ContextRecovery](./ContextRecovery.py): Iterates over calls to the string
  deobfuscation function, recovers the call parameters, and decrypts
  the obfuscated strings.

## Extremely cool things

* [DumpFunctionAST](./DumpFunctionAST.py): pretty print a function structure (AST)
  as recovered by the decompiler. This is novel, because as far as I know nobody
  shared a script that does this before.

# Examples

Some examples of how to use the library in practice (a lot of this is code
I wrote during my work as a reverse-engineer).

Since this library is still in development, there's not much to show off yet.
But I plan to share snippets of things I write during my daily work here.

## Basics

Scripts to serve as examples, and maybe to ensure everything works smoothly in ghidralib.
Scripts here are often rewritten Ghidra examples, or very small deobfuscation scripts.

* [SwitchOverride](./SwitchOverride.py): Fixup a switch statement at the pointer location.

## Everyday use

* [ContextRecovery](./ContextRecovery.py): Iterates over calls to the string
  deobfuscation function, recovers the call parameters, and decrypts
  the obfuscated strings.
* [FixUnaffectedRegisters](./FixUnaffectedRegisters.py): Fix broken "unaffected" registers
  in the whole program by traversing the call graph and editing function signatures.
* [RecoverFunctionPointers](./RecoverFunctionPointers.py): Recovering function pointers.
  Iterate over MOVs in a function, and use the decompilation of the function referenced
  by the second MOV operand to automatically rename and retype the function pointer from the
  first parameter. And all of that in just ~20 lines of code!

## Pretty cool things

* [DumpFunctionAST](./DumpFunctionAST.py): pretty print a function structure (AST)
  as recovered by the decompiler. This is novel: as far as I know there was no
  publicly available script that did this.

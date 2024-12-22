# Program Model

Ghidra models all kinds of various objects encountered during reverse-engineering:
functions, instructions, basic blocks, datatypes... All that entities
live in the `ghidra.program.model` namespace. Since they are crucial for
any scripting, ghidralib wraps many of them. In this section we'll take a closer
look at them and how to use them.


provides a structured framework for
understanding and analyzing the components of a binary program. It includes
essential elements like instructions, basic blocks, functions, and symbols,
which together define the program's logic and structure. This namespace is
crucial for reverse engineering, as it enables efficient navigation, analysis,
and manipulation of the program's code and data.

## Foobar

::: ghidralib.Function
    handler: python
    options:
        show_if_no_docstring: true
        show_root_heading: true
        show_source: true

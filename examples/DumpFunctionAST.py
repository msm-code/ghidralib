# Licensed under Apache 2.0
#
# Dump a function AST, by leveraging DecompilerInterface.structureGraph method. Inspired by DecompilerNestedLayout class.
# As far as I know, there was no publicly available Ghidra code to recover Pcode AST before this, see issues:
# https://github.com/NationalSecurityAgency/ghidra/discussions/4314
# https://github.com/NationalSecurityAgency/ghidra/issues/2204
# https://github.com/NationalSecurityAgency/ghidra/discussions/6771

from ghidralib import *


def dump(graph, ind=""):
    for block in graph.blocks:
        print("{} ({}): ".format(ind, block))
        if block.is_graph:
            dump(block, ind + "  ")
        else:
            for op in block.pcode:
                print("{}  {:x} {}".format(ind + "  ", op.address, op))


outgraph = Function("main").get_high_function().get_ast()
dump(outgraph)

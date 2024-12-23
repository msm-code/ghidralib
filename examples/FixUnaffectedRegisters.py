# Licensed under Apache 2.0
#
# A fix for https://github.com/NationalSecurityAgency/ghidra/discussions/5186
#
# Go over all defined functions, from bottom to the top, and recover missing arguments.
# In particular, this will look for unaffixed and input variables that are registers,
# and add them as parameters to the function.
#
# Another solution would be to check if var.is_input and variable is not a
# parameter, but the current solution was easier to implement.

from ghidralib import *

for func in Program.call_graph().toposort(Function("_start"))[::-1]:
    for var in func.high_variables:
        if (var.is_input or var.is_unaffected) and var.varnode.is_register:
            regname = var.varnode.as_register
            print("adding {} to {}".format(regname, func.name))
            func.add_register_parameter("uint", regname, "arg_" + regname)

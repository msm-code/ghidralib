# Compatibility

This library uses unstable Ghidra APIs, so it's expected to break from time to time
(when Ghidra changes internal implementation details).

In this document I'll keep track of the compatibility status of the library. I don't
to backport fixes and do complex hacks to support more than one Ghidra version at once.
Instead, for each Ghidra version I'll try to provide a working ghidralib version.

Keep in mind, that this library is still in rapid development, and the API may and will
change before we reach the first stable release (v1.0).

### Compatibility matrix

Here is a compatibility matrix of tested Ghidra and ghidralib versions:

ghidralib \ ghidra  | 11.2.1  |
--------------------|---------|
0.1.0               | ✅      |

(Compatibility is checked by running a [testsuite](../tests/ghidralib_test.py)
on a test binary)

### Architectures

I work almost exclusively on x86 and x86_64, so the library is tested
on these architectures. There is nothing specific to x86 in the code,
but I expect that some exotic architectures will not work correctly.
Freel free to submit issues/PRs if you find something is broken.

### Python 3

I plan to support the Python 3 built into Ghidra (PyGhidra), as soon as it's released
and I manage to get it working. I hope to support both Jython and Python3
with the same codebase.

I don't personally use Ghidrathon, so I don't plan to provide any support for it.
That would be nice to have, and I suspect the steps required are the same as for
PyGhidra, so if anyone wants to take a shot at it, PRs are welcome.

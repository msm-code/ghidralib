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

ghidralib \ ghidra  | 11.2.1  | 11.3 (dev) |
--------------------|---------| -----------|
0.1.0               | ✅      |            |
0.2.0               | ✅      | ✅         |

(Compatibility is checked by running a [testsuite](../tests/ghidralib_test.py)
on a test binary)

### Architectures

I work almost exclusively on x86 and x86_64, so the library is tested
on these architectures. There is nothing specific to x86 in the code,
but I expect that some exotic architectures will not work correctly.
Freel free to submit issues/PRs if you find something is broken.

### Python 3

Basic Python 3 (PyGhidra) is implemented. Right now it's unstable.

Known problems:

* It will only work on the program you had open when you loaded ghidralib.
  To switch to another program, `del sys.modules["ghidralib"]` and import again.

I don't personally use Ghidrathon, so I didn't test Ghidrathon compatibility.

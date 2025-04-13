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

ghidralib \ ghidra  |11.2.1|11.3|11.3.2|
--------------------|------|----|------|
0.1.0               |✅    |    |      |
0.2.0               |✅    | ✅ | ✅   |

(Compatibility is checked by running a [testsuite](https://github.com/msm-code/ghidralib/blob/master/tests/ghidralib_test.py)
on a test binary)

### Architectures

I work almost exclusively on x86 and x86_64, so the library is tested
on these architectures. There is nothing specific to x86 in the code,
but I expect that some exotic architectures will not work correctly.
Freel free to submit issues/PRs if you find something is broken.

### Python 3

The script is Python 3 compatible. Ghidralib builds are tested using PyGhidra. Right now the support is unstable.

Known problems:

* Ghidralib will **always** work on the program that you had open when you imported
  Ghidralib. Because of this, using ghdiralib on multiple programs at once may cause chaos.
  To switch Ghidralib to another program, just `del sys.modules["ghidralib"]` and import it again.
  This issue is because of the differences in how Jython and PyGhidra work, and I believe it's
  unsolvable currently (upstream discussion: https://github.com/NationalSecurityAgency/ghidra/issues/8011)

I don't personally use Ghidrathon, so I didn't test Ghidrathon compatibility.

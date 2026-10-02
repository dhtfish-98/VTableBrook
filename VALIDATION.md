# Validation

The original source and modular derivative both build with Clang at O0 and O2.

- 194 real-process comparisons pass on 97 owned inputs at both optimization levels; exit status, stdout/stderr and extracted-file bytes match.
- All 13 executable function bodies match after inverse identifier normalization in Clang ASTs. Only locations, compiler-memory declaration identities and the intended move from file-local functions to modular linkage are normalized.
- The fixture covers valid records, selection boundaries, unsupported headers, empty inputs and generated class/vtable flows.

No live device or arbitrary third-party kernel image is claimed as validated. The inherited parser is not a hardened parser for arbitrary malformed or hostile data. Existing behavior is preserved rather than presented as repaired or universally safe.

GitHub CI checks out the exact upstream commit and reruns these checks. Release assets include the corresponding source, GPL license and separately packaged macOS executable.

## 2026-10-02 capability review

The current runtime entry points, file/process/network capabilities and attribution were reviewed. See DEFENSIVE_SCOPE.md for the exact paths and remaining limitations. This documentation update does not claim another execution of the historical full test suite, a rewrite of every upstream algorithm, or CVP eligibility. GitHub CI for the new commit is separate evidence.

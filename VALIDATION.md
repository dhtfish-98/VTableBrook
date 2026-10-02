# Validation — current bounded rewrite (2026-10-02)

The current gate is `checks/vtablebrook_safety.py`, reproduced by GitHub CI against the pinned upstream source. Local results are in [CURRENT_VALIDATION.json](CURRENT_VALIDATION.json).

- **182 process/output comparisons pass** on 91 owned compatible fixtures at O0 and O2. Exit status, stdout/stderr, unchanged input and absence of analysis-created files are checked. Builds use warnings as errors.
- **230 sanitizer/boundary checks pass**, including 160 deterministic mutations at actual header, section and pointer read sites. AddressSanitizer and UndefinedBehaviorSanitizer check the current runtime. macOS leak detection is disabled because it is unavailable; no leak-sanitizer result is claimed.
- **13 independently assembled ARM64 cases pass**, covering immediate width/shift, logical-immediate element repetition/rotation, shifted ADD, MOV register and SP/XZR distinctions. These are static bytes, never executed as input code.
- The thirteenth metaclass pointer, string termination, half-open address ranges, address overflow, unaligned pointers, short command/section data and unsupported linear mapping are checked.
- Record count, instruction work, initializer count, name size and report-byte limits are exercised. The report-byte limit emits only complete records and returns error status. Final-path symlinks, FIFOs, directories, missing files, empty files and a sparse file exceeding 1 GiB are refused promptly.
- The actual `make install` target and a consumer outside the source tree reproduce the expected normal record.

## Intentional changes

Invalid usage, malformed/unsupported input and exceeded limits now return exit 2. Printable normal records remain compatible. Class-name control bytes, non-ASCII bytes and backslashes are escaped. Unknown tracked registers are not asserted to contain zero. The parser checks the full thirteen-entry table and refuses reads outside the file/code/name spans.

The old bootstrap scan could continue after RET into another function. Two O0/O2 comparisons separately confirm that the historical fixture printed a class after this unreachable call while the current scan stops with an empty result. This is an intentional correction, not counted among the 182 equal-output cases. MOVZ/ADD shifts and repeated ORR immediate elements are interpreted with their operand semantics; no equivalence to the old incorrect operand interpretation is claimed.

## Historical evidence

Before this rewrite, 194 comparisons on 97 inputs and 13 normalized function AST comparisons passed for the initial modular derivative. The old `vtablebrook_equivalence.py`, `vtablebrook_structure.py` and `RENAME_MAP.json` remain provenance for the v1.0.0 checkout. They do not establish AST equality or invalid-input status equality for the current implementation and are no longer the current CI gates.

## Limits of the result

Evidence covers owned synthetic, linear-layout ARM64 Mach-O files and finite malformed inputs. It does not prove arbitrary-input safety, class-discovery completeness, every ARM64 instruction or kernel release, real-device behavior, or CVP eligibility/approval. The analyzer is a straight-line pattern heuristic; it does not model all control flow or clobbering by unknown instructions and function calls. Printed addresses and sizes are candidate interpretations.

The input loader avoids memory-mapped truncation faults and checks descriptor metadata and complete reads. This is not a guaranteed coherent snapshot of data concurrently modified by another writer. v1.0.1 distributes current source only; the old v1.0.0 packaged executable is historical.

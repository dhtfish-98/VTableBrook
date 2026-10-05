# Source lineage

VTableBrook derives from [vtable](https://github.com/0x7ff/vtable) at commit `7ffffff929983e3cc4c8155e66fd954acbb1008e`. The pinned `vtable.c` SHA-256 is `c11a111f00914ba496b356ea87e6e4c1120b7b9eaa313d92abbe45476c664085` and is checked before differential validation.

The original GPL-3.0 license and author notices remain. The first version renamed implementation bindings and split the original code across modules. `RENAME_MAP.json` and the historical AST check describe that first transformation; they are not a map of the current rewritten function bodies.

On 2026-10-02, all four runtime C files and their shared header were rewritten into explicit image spans, checked reads, a bounded static pattern interpreter and a regular-file loader. The class-constructor/allocator discovery conventions still derive from upstream. This maintenance is not evidence that the applicant independently originated the upstream algorithms.

ARM64 immediate semantics were checked against primary LLVM documentation/source, including [AArch64 addressing-mode helpers](https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/AArch64/MCTargetDesc/AArch64AddressingModes.h). The current decoder uses its own per-bit mask construction; it does not copy LLVM implementation code. Test operands are independently assembled by Clang and are never executed.

The historical v1.0.0 source/binary release is retained. The v1.0.1 source
release contains the bounded rewrite. The current v1.0.2 source release adds
the centralized documentation and Build staging layout without changing the
runtime. Neither source release makes an updated-binary or live-device claim.

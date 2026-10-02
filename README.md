# VTableBrook

VTableBrook performs offline, static class and virtual-table pattern analysis on compatible little-endian ARM64 Mach-O kernel files that you own or are authorized to inspect. The runtime reads one local file and prints a report; it does not run kernel instructions, contact a network, edit the input or create analysis files.

The 2026-10-02 implementation rewrites all four C translation units and their shared header around a bounded image context. Analysis still derives from the attributed upstream project in [ORIGIN.md](ORIGIN.md); original GPL notices remain. Defensive use and CVP evidence boundaries are in [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md).

## Build and use

macOS with Clang and Apple's Mach-O headers is required.

```sh
make
./vtablebrook /path/to/owned-kernel-image
make install DESTDIR=/tmp/vtablebrook-install PREFIX=/usr/local
```

For compatible recognized patterns, printable ASCII records retain the original `Name`, `metaclass`, `vtable` and `size` layout. Nonprintable name bytes and backslashes are escaped as `\xHH`. Exit 0 means processing finished within the supported pattern and limits; an empty report does not prove an image has no classes. Exit 2 means usage, input, layout, resource or output failure. Any lines printed before exit 2 are an incomplete report.

Only regular, nonempty files up to 1 GiB are accepted. The final path component must not be a symlink. A private heap copy replaces the old file mapping, with checks for short reads and detectable file changes. Intermediate-directory symlinks remain permitted; this is not path confinement or a guaranteed coherent capture of a concurrently modified file.

## Supported analysis and limits

The tool retains the upstream high-half pointer normalization, second bootstrap pointer and metaclass allocator entry 12 convention. Selected sections must use the linear kernel layout `file offset = virtual address - __TEXT base`; unsupported nonlinear layouts return an error. Container bounds are checked before access, including all 13 entries needed for a metaclass table.

Static patterns cover BL, ADRP, ADD immediate, MOV X register, MOVZ W/X, ORR W immediate, zero-offset STR X and RET X30. This is a finite straight-line heuristic. It does not follow arbitrary control flow, simulate memory, resolve every relocation or model general register clobbering by unknown instructions and called functions. Reported values are candidates requiring separate confirmation. Return instructions stop discovery; unknown tracked values are not reported as proven zeros.

Limits are 8,192 load commands, 65,536 section descriptors, 65,536 initializer entries, 4,194,304 total scanned instructions, 4,096 printed records, 64 KiB per class name and 16 MiB total report bytes. A limit failure returns exit 2 rather than a successful truncated result.

## Reproduce current verification

Check out the pinned upstream commit in [ORIGIN.md](ORIGIN.md) outside this tree, then run:

```sh
make
python3 checks/vtablebrook_safety.py --reference /path/to/upstream/vtable.c
```

This gate checks normal output against the pinned source at O0/O2, malformed input under address/undefined-behavior sanitizers, independently assembled ARM64 operands, unchanged input, no analysis-created files and an installed consumer outside the source tree. See [VALIDATION.md](VALIDATION.md) for finite evidence and intentional behavior changes.

Current source release v1.0.1 contains source only. The old v1.0.0 executable remains historical and does not include this rewrite.

"""Current bounded-parser gate; historical AST/invalid-status equivalence is separate."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import random
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('historical_fixtures', ROOT / 'checks/vtablebrook_equivalence.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
HIGH = 0xFFFF000000000000
BASE = fixtures.review_vtable_image(80, 'OwnedClass', 'normal')


def patch(blob, offset, fmt, value):
    changed = bytearray(blob)
    struct.pack_into(fmt, changed, offset, value)
    return bytes(changed)


def instructions(blob, offset, words):
    changed = bytearray(blob)
    struct.pack_into('<' + str(len(words)) + 'I', changed, offset, *words)
    return bytes(changed)


def expected(name='OwnedClass', size=80, table=HIGH + 0x3400, metaclass=HIGH + 0x2400):
    return f'Name: {name}, metaclass: 0x{metaclass:016x}, vtable: 0x{table:016x}, size: 0x{size:x}\n'.encode()


def assemble(work, source):
    """Use Clang's ARM64 assembler; never execute generated object code."""
    assembly = work / 'owned.s'
    output = work / 'owned.o'
    assembly.write_text('.text\n' + source + '\n')
    subprocess.run(['clang', '-target', 'arm64-apple-macos11.0', '-c', str(assembly), '-o', str(output)], check=True, capture_output=True)
    blob = output.read_bytes()
    magic, _, _, _, count, _, _, _ = struct.unpack_from('<8I', blob)
    assert magic == 0xFEEDFACF
    cursor = 32
    for _ in range(count):
        command, length = struct.unpack_from('<II', blob, cursor)
        if command == 0x19:
            sections = struct.unpack_from('<I', blob, cursor + 64)[0]
            for i in range(sections):
                position = cursor + 72 + i * 80
                if blob[position:position + 16].rstrip(b'\0') == b'__text':
                    size, offset = struct.unpack_from('<QI', blob, position + 40)
                    data = blob[offset:offset + size]
                    return list(struct.unpack('<' + str(len(data) // 4) + 'I', data))
        cursor += length
    raise AssertionError('assembler did not emit __text')


def run(binary, blob, folder, status=0, output=None, error=None):
    folder.mkdir()
    image = folder / 'owned-image'
    image.write_bytes(blob)
    digest = hashlib.sha256(blob).hexdigest()
    done = subprocess.run([str(binary), str(image)], cwd=folder, capture_output=True, timeout=10,
                          env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0:abort_on_error=1',
                               'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'})
    assert done.returncode == status, (folder.name, done.returncode, done.stderr[:2000])
    if output is not None: assert done.stdout == output, (folder.name, done.stdout[:2000], output[:2000])
    if status == 0: assert not done.stderr, (folder.name, done.stderr)
    if error is not None: assert error in done.stderr, (folder.name, done.stderr)
    assert b'Sanitizer' not in done.stderr and b'runtime error:' not in done.stderr, (folder.name, done.stderr)
    assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
    assert {p.name for p in folder.iterdir()} == {'owned-image'}, folder.name
    return done


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    options = parser.parse_args()
    lineage = json.loads((ROOT / 'RENAME_MAP.json').read_text())
    assert hashlib.sha256(options.reference.read_bytes()).hexdigest() == lineage['reference_source_sha256']
    comparisons = checks = 0
    rng = random.Random(20261002)
    valid = [(fixtures.review_vtable_image(size := rng.randrange(65536), f'OwnedClass{i}', 'normal'),
              expected(f'OwnedClass{i}', size)) for i in range(90)]
    valid += [(fixtures.review_vtable_image(32, 'OwnedClass', 'ret'), b'')]
    with tempfile.TemporaryDirectory(prefix='vtablebrook-current-') as temporary:
        work = Path(temporary)
        sources = [str(p) for p in sorted((ROOT / 'Sources').glob('*.c'))]
        for optimization in ['O0', 'O2']:
            previous = work / ('upstream-' + optimization)
            current = work / ('current-' + optimization)
            subprocess.run(['clang', '-std=c99', '-' + optimization, str(options.reference.resolve()), '-o', str(previous)], check=True)
            subprocess.run(['clang', '-std=c99', '-Wall', '-Wextra', '-Werror', '-pedantic', '-' + optimization, *sources, '-o', str(current)], check=True)
            for i, (blob, wanted) in enumerate(valid):
                left = run(previous, blob, work / f'left-{optimization}-{i}', output=wanted)
                right = run(current, blob, work / f'right-{optimization}-{i}', output=wanted)
                assert (left.returncode, left.stdout, left.stderr) == (right.returncode, right.stdout, right.stderr)
                comparisons += 1
            after_return = fixtures.review_vtable_image(32, 'OwnedClass', 'no-call')
            run(previous, after_return, work / f'unreachable-old-{optimization}', output=expected(size=32))
            run(current, after_return, work / f'unreachable-new-{optimization}', output=b'')
        sanitized = work / 'current-sanitized'
        subprocess.run(['clang', '-std=c99', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O1', '-g',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', *sources, '-o', str(sanitized)], check=True)
        def check(blob, status=0, output=None, error=None):
            nonlocal checks
            result = run(sanitized, blob, work / f'safety-{checks}', status, output, error)
            checks += 1
            return result
        check(BASE, output=expected())
        # Mach-O structural limits and arithmetic boundaries at the actual read sites.
        malformed = [b'', b'\xcf', BASE[:31], fixtures.review_header(0, 0, 7),
                     fixtures.review_header(0, 0, review_magic=0),
                     patch(BASE, 16, '<I', 0xFFFFFFFF), patch(BASE, 20, '<I', 0xFFFFFFFF),
                     patch(BASE, 36, '<I', 0), patch(BASE, 36, '<I', 7), patch(BASE, 36, '<I', 9),
                     patch(BASE, 36, '<I', 0xFFFFFFF8), patch(BASE, 96, '<I', 0xFFFFFFFF),
                     patch(BASE, 56, '<Q', 0xFFFFFFFFFFFFFFFF), patch(BASE, 64, '<Q', 0xFFFFFFFFFFFFFFFF), patch(BASE, 72, '<Q', 0xFFFFFFFFFFFFFFFF),
                     patch(BASE, 80, '<Q', 0xFFFFFFFFFFFFFFFF), patch(BASE, 80, '<Q', len(BASE) + 1),
                     patch(BASE, 104 + 32, '<Q', 0xFFFFFFFFFFFFFFFF),
                     patch(BASE, 104 + 40, '<Q', 0xFFFFFFFFFFFFFFFF),
                     patch(BASE, 104 + 48, '<I', len(BASE)),
                     patch(BASE, 104 + 32, '<Q', HIGH - 1),
                     patch(BASE, 104 + 48, '<I', 0x1001),
                     patch(BASE, 104 + 16, '<I', 0x41414141),
                     patch(BASE, 256 + 40, '<Q', 9), # __DATA initializer section
                     patch(BASE, 408 + 40, '<Q', 8), # bootstrap missing entry[1]
                     patch(BASE, 560 + 40, '<Q', 0x7FF),
                     patch(BASE, 560 + 32, '<Q', HIGH + 0x3001),
                     patch(BASE, 0x2208, '<Q', 0x2FFC), patch(BASE, 0x2208, '<Q', 0x3800),
                     patch(BASE, 0x2208, '<Q', 0x3001), patch(BASE, 0x2300, '<Q', 0x3800),
                     patch(BASE, 0x2300, '<Q', 0x3201), patch(BASE, 0x2300, '<Q', 0xFFFFFFFFFFFFFFFF),
                     patch(BASE, 0x2460, '<Q', 0x3301)]
        for blob in malformed: check(blob, 2, output=b'')
        check(fixtures.review_header(0, 0), output=b'')
        check(patch(BASE, 0x2300, '<Q', 0), output=b'')
        check(patch(BASE, 0x2208, '<Q', 0), output=b'')
        # Unterminated/control-byte names, half-open name bounds and the thirteenth table entry.
        missing_nul = bytearray(BASE); missing_nul[0x1000:0x1080] = b'A' * 128
        check(bytes(missing_nul), 2, output=b'', error=b'unterminated')
        escaped = bytearray(BASE); escaped[0x1000:0x1007] = b'A\n\x1b\\\xffZ\0'
        check(bytes(escaped), output=expected(r'A\x0a\x1b\x5c\xffZ'))
        check(patch(BASE, 0x3204, '<I', 0x91000021 | (128 << 10)), output=b'')
        # The table starts within the file but entry[12] does not fit: old one-entry guard missed this.
        words = [fixtures.review_adrp(2, 0x3208, 0x4FA0), 0x91000042 | (0xFA0 << 10)]
        check(instructions(BASE, 0x3208, words), 2, output=b'', error=b'metadata pointer')
        check(patch(BASE, 0x320C, '<I', 0x91000042 | (0x401 << 10)), 2, output=b'', error=b'aligned')
        # Null/out-of-section allocators retain the metaclass-only record; unknown registers are not asserted as zero.
        meta_only = b'Name: OwnedClass, metaclass: 0xffff000000002400\n'
        check(patch(BASE, 0x2460, '<Q', 0), output=meta_only)
        check(patch(BASE, 0x2460, '<Q', 0x3800), output=meta_only)
        check(instructions(BASE, 0x3300, [0xF9000003, 0xD65F03C0]), output=meta_only)
        # ARM64 independently assembled operands: MOVZ width/shift, ORR element repetition/rotation, ADD shift, MOV alias.
        tail = list(struct.unpack_from('<4I', BASE, 0x3304))
        for immediate in [0xFF, 0xFF00, 0x80000000, 0x80000001, 0xAAAAAAAA, 0x00FF00FF, 0x0F0F0F0F, 0xFFFF0000]:
            compiled = assemble(work, f'orr w0, wzr, #0x{immediate:x}')
            check(instructions(BASE, 0x3300, compiled + tail), output=expected(size=immediate))
        compiled = assemble(work, 'movz w0, #0x12, lsl #16\norr w0, w0, #0xff')
        check(instructions(BASE, 0x3300, compiled + tail), output=expected(size=0x1200FF))
        compiled = assemble(work, 'movz x0, #0x12, lsl #48')
        check(instructions(BASE, 0x3300, compiled + tail), output=expected(size=0x12000000000000))
        compiled = assemble(work, 'add x3, x3, #1, lsl #12')
        check(patch(BASE, 0x3308, '<I', compiled[0]), output=expected(table=HIGH + 0x4000))
        compiled = assemble(work, 'mov x2, x4')
        updated = instructions(BASE, 0x3208, [fixtures.review_adrp(4, 0x3208, 0x2400), 0x91000084 | (0x400 << 10),
                                            compiled[0], 0x94000000 | (((0x3100 - 0x3214) // 4) & 0x3FFFFFF),
                                            0xF9000002, 0xD65F03C0])
        check(updated, output=expected())
        # ADD to SP must not change the architectural XZR value read by ORR.
        compiled = assemble(work, 'movz x5, #7\nadd sp, x5, #1\norr w0, wzr, #0xff')
        check(instructions(BASE, 0x3300, compiled + tail), output=expected(size=0xFF))
        # A BL after RET is unreachable for this straight-line discovery pattern.
        check(instructions(BASE, 0x3000, [0xD65F03C0, 0x94000000 | ((0x3100 - 0x3004) // 4)]), output=b'')
        # Deterministic read-site mutations must finish without a signal, sanitizer report, or input/output mutation.
        locations = [(16, '<I'), (20, '<I'), (36, '<I'), (96, '<I'),
                     (136, '<Q'), (144, '<Q'), (152, '<I'), (296, '<Q'),
                     (448, '<Q'), (600, '<Q'), (0x2208, '<Q'), (0x2300, '<Q'), (0x2460, '<Q')]
        for i in range(160):
            offset, fmt = locations[i % len(locations)]
            changed = patch(BASE, offset, fmt, rng.getrandbits(32 if fmt == '<I' else 64))
            folder = work / f'mutation-{i}'
            folder.mkdir(); path = folder / 'owned-image'; path.write_bytes(changed)
            done = subprocess.run([str(sanitized), str(path)], cwd=folder, capture_output=True, timeout=10,
                                  env={**os.environ, 'ASAN_OPTIONS':'abort_on_error=1', 'UBSAN_OPTIONS':'halt_on_error=1'})
            assert done.returncode in [0, 2], (i, done.returncode, done.stderr)
            assert b'Sanitizer' not in done.stderr and b'runtime error:' not in done.stderr, (i, done.stderr)
            assert path.read_bytes() == changed and {p.name for p in folder.iterdir()} == {'owned-image'}
            checks += 1
        # Limits: initializer count, global work and per-report records. The count fixture is rejected before scanning.
        many = bytearray(BASE); many.extend(bytes(65537 * 8)); pointer_offset = 0x5000
        struct.pack_into('<QQI', many, 256 + 32, HIGH + pointer_offset, 65537 * 8, pointer_offset)
        check(bytes(many), 2, output=b'', error=b'initializer limit')
        repeated = bytearray(BASE); repeated.extend(bytes(65536 * 8))
        struct.pack_into('<QQI', repeated, 256 + 32, HIGH + 0x5000, 65536 * 8, 0x5000)
        for i in range(65536): struct.pack_into('<Q', repeated, 0x5000 + i * 8, 0x3200)
        done = check(bytes(repeated), 2, error=b'record or output limit')
        assert done.stdout.count(b'Name: ') == 4096
        no_records = instructions(bytes(repeated), 0x3200, [0xD503201F] * ((0x3800 - 0x3200) // 4))
        check(no_records, 2, output=b'', error=b'instruction limit')
        # A large repeated name reaches output limit before record limit, without a partial record.
        long_name = bytearray(repeated); long_name.extend(b'A' * 65536 + b'\0')
        name_offset = len(repeated)
        struct.pack_into('<QQI', long_name, 104 + 32, HIGH + name_offset, 65537, name_offset)
        long_name = instructions(bytes(long_name), 0x3200, [fixtures.review_adrp(1, 0x3200, name_offset),
                                                          0x91000021 | ((name_offset & 0xFFF) << 10)])
        done = check(long_name, 2, error=b'record or output limit')
        assert len(done.stdout) <= 16777216 and done.stdout.endswith(b'\n')
        # Final-path symlinks, FIFO, directory, missing input and sparse over-limit input are refused promptly.
        special = work / 'special'; special.mkdir()
        target = special / 'target'; target.write_bytes(BASE)
        (special / 'link').symlink_to(target); os.mkfifo(special / 'fifo')
        oversized = special / 'oversized'
        with oversized.open('wb') as stream: stream.truncate(1073741825)
        for path in [special / 'link', special / 'fifo', special, special / 'missing', oversized]:
            done = subprocess.run([str(sanitized), str(path)], capture_output=True, timeout=5)
            assert done.returncode == 2 and not done.stdout, (path.name, done.returncode, done.stderr)
            checks += 1
        assert target.read_bytes() == BASE and oversized.stat().st_size == 1073741825
        done = subprocess.run([str(sanitized)], capture_output=True, timeout=5)
        assert done.returncode == 2 and b'Usage:' in done.stderr
        checks += 1
        # Actual install target and outside-tree consumer, not only an in-tree executable.
        subprocess.run(['make', 'install', f'DESTDIR={work / "consumer"}', 'PREFIX=/usr/local'], cwd=ROOT, check=True, capture_output=True)
        run(work / 'consumer/usr/local/bin/vtablebrook', BASE, work / 'installed-run', output=expected())
    result = {'status':'PASS', 'valid_process_comparisons':comparisons, 'valid_fixture_inputs':len(valid),
              'optimization_levels':['O0','O2'], 'sanitizer_and_boundary_checks':checks,
              'sanitizers':['AddressSanitizer','UndefinedBehaviorSanitizer'], 'independent_arm64_assembler_vectors':13, 'intentional_ret_discovery_changes':2,
              'installed_consumer':'PASS', 'input_immutability_and_no_created_files':'PASS',
              'reference_sha256':lineage['reference_source_sha256'],
              'scope':'Owned synthetic linear-layout ARM64 Mach-O data. No input execution, live kernel, device, or CVP approval.'}
    if options.output: options.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__ == '__main__': main()

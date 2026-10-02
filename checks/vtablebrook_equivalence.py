# Historical v1.0.0 verification. See vtablebrook_safety.py for the current rewrite.
"""Compare a modular derivative with a pinned upstream source on owned fixtures."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import random
import struct
import subprocess
import tempfile

def review_header(review_commands, review_command_bytes, review_cpu=0x0100000C, review_magic=0xFEEDFACF):
    return struct.pack('<8I', review_magic, review_cpu, 0, 2, review_commands, review_command_bytes, 0, 0)

def review_section(review_label, review_region, review_address, review_length, review_offset, review_kind=0):
    return struct.pack('<16s16sQQ8I', review_label.encode(), review_region.encode(), review_address,
                       review_length, review_offset, 0, 0, 0, review_kind, 0, 0, 0)

def review_region(review_label, review_address, review_length, review_sections):
    return struct.pack('<II16sQQQQ4I', 0x19, 72 + 80 * len(review_sections), review_label.encode(),
                       review_address, review_length, 0, review_length, 7, 5, len(review_sections), 0) + b''.join(review_sections)

def review_extract_image(review_count, review_rng):
    review_high = 0xFFFF000000000000
    review_blob = bytearray(0x10000)
    review_commands = [review_region('__TEXT', review_high, len(review_blob), []),
                       review_region('__PRELINK_INFO', review_high, len(review_blob), [
                           review_section('__kmod_start', '__PRELINK_INFO', review_high + 0x1000, review_count * 8, 0x1000),
                           review_section('__kmod_info', '__PRELINK_INFO', review_high + 0x1200, review_count * 8, 0x1200)])]
    review_blob[:32] = review_header(len(review_commands), sum(map(len, review_commands)))
    review_blob[32:32 + sum(map(len, review_commands))] = b''.join(review_commands)
    for review_index in range(review_count):
        review_child = 0x4000 + review_index * 0x500
        review_record = 0x1800 + review_index * 0x100
        struct.pack_into('<Q', review_blob, 0x1000 + review_index * 8, review_child)
        struct.pack_into('<Q', review_blob, 0x1200 + review_index * 8, review_record)
        review_label = 'owned.extension.' + str(review_index)
        review_version = str(review_rng.randrange(100)) + '.fixture'
        struct.pack_into('<Qii64s64s', review_blob, review_record, 0, 1, review_index,
                         review_label.encode(), review_version.encode())
        review_child_region = review_region('__TEXT_EXEC', review_child, 0x300, [
            review_section('__text', '__TEXT_EXEC', review_child + 0x100, 0x100, 0x100)])
        review_blob[review_child:review_child + 0x300] = review_rng.randbytes(0x300)
        review_blob[review_child:review_child + 32] = review_header(1, len(review_child_region))
        review_blob[review_child + 32:review_child + 32 + len(review_child_region)] = review_child_region
    return bytes(review_blob)

def review_adrp(review_register, review_current, review_target):
    review_pages = ((review_target & ~0xFFF) - (review_current & ~0xFFF)) // 4096
    review_encoded = review_pages & ((1 << 21) - 1)
    return 0x90000000 | ((review_encoded & 3) << 29) | ((review_encoded >> 2) << 5) | review_register

def review_vtable_image(review_size, review_label, review_path):
    review_high = 0xFFFF000000000000
    review_blob = bytearray(0x5000)
    review_commands = [
        review_region('__TEXT', review_high, len(review_blob), [review_section('__cstring', '__TEXT', review_high + 0x1000, 128, 0x1000, 2)]),
        review_region('__DATA', review_high + 0x2000, 0x1000, [review_section('__mod_init_func', '__DATA', review_high + 0x2300, 8, 0x2300, 9)]),
        review_region('__DATA_CONST', review_high + 0x2000, 0x1000, [review_section('__mod_init_func', '__DATA_CONST', review_high + 0x2200, 16, 0x2200, 9)]),
        review_region('__TEXT_EXEC', review_high + 0x3000, 0x800, [review_section('__text', '__TEXT_EXEC', review_high + 0x3000, 0x800, 0x3000)])]
    review_blob[:32] = review_header(len(review_commands), sum(map(len, review_commands)))
    review_blob[32:32 + sum(map(len, review_commands))] = b''.join(review_commands)
    review_blob[0x1000:0x1000 + len(review_label) + 1] = review_label.encode() + b'\0'
    struct.pack_into('<2Q', review_blob, 0x2200, 0, 0x3000)
    struct.pack_into('<Q', review_blob, 0x2300, 0x3200)
    struct.pack_into('<Q', review_blob, 0x2400 + 12 * 8, 0x3300)
    review_boot = [0x94000000 | ((0x3100 - 0x3000) // 4), 0xD65F03C0]
    review_init = [review_adrp(1, 0x3200, 0x1000), 0x91000000 | (1 << 5) | 1,
                   review_adrp(2, 0x3208, 0x2400), 0x91000000 | (0x400 << 10) | (2 << 5) | 2,
                   0x94000000 | (((0x3100 - 0x3210) // 4) & 0x3FFFFFF), 0xF9000002, 0xD65F03C0]
    review_alloc = [0x52800000 | ((review_size & 0xFFFF) << 5), review_adrp(3, 0x3304, 0x3400),
                    0x91000000 | (0x400 << 10) | (3 << 5) | 3, 0xF9000003, 0xD65F03C0]
    if review_path == 'ret': review_init = [0xD65F03C0]
    if review_path == 'no-call': review_boot = [0xD65F03C0] * 512
    for review_offset, review_words in [(0x3000, review_boot), (0x3200, review_init), (0x3300, review_alloc)]:
        struct.pack_into('<' + str(len(review_words)) + 'I', review_blob, review_offset, *review_words)
    return bytes(review_blob)

def review_run(review_binary, review_fixture, review_input, review_folder, review_noargs=False):
    review_folder.mkdir()
    review_path = review_folder / 'owned-image'
    review_path.write_bytes(review_fixture)
    review_args = [str(review_binary)] + ([] if review_noargs else [str(review_path)])
    review_done = subprocess.run(review_args, input=review_input, cwd=review_folder, capture_output=True, timeout=5)
    review_output = review_done.stdout.replace(str(review_binary).encode(), b'<program>')
    review_files = {review_file.name: hashlib.sha256(review_file.read_bytes()).hexdigest()
                    for review_file in review_folder.iterdir() if review_file.name != 'owned-image'}
    return review_done.returncode, review_output, review_done.stderr, review_files

def review_main():
    review_parser = argparse.ArgumentParser()
    review_parser.add_argument('--reference', type=Path, required=True)
    review_parser.add_argument('--output', type=Path)
    review_options = review_parser.parse_args()
    review_root = Path(__file__).resolve().parents[1]
    review_map = json.loads((review_root / 'RENAME_MAP.json').read_text())
    assert hashlib.sha256(review_options.reference.read_bytes()).hexdigest() == review_map['reference_source_sha256'], 'Reference bytes must match the pinned upstream source.'
    review_project = review_map['project']
    review_rng = random.Random(20261002)
    review_cases = [(review_header(0, 0), b'', False), (review_header(0, 0, 7), b'', False),
                    (review_header(0, 0, review_magic=0), b'', False), (b'', b'', False), (b'', b'', True)]
    if review_project == 'KernelCabinet':
        for review_number in range(0, 9):
            for review_choice in [-1, 0, review_number // 2, review_number - 1, review_number, review_number + 1]:
                review_cases.append((review_extract_image(review_number, review_rng), (str(review_choice) + '\n').encode(), False))
        review_cases.extend((review_extract_image(3, review_rng), review_input, False) for review_input in [b'x\n', b'\n', b'2tail\n', b'9999999999999999999999999999999\n'])
    else:
        for review_number in range(90):
            review_cases.append((review_vtable_image(review_rng.randrange(65536), 'OwnedClass' + str(review_number), 'normal'), b'', False))
        review_cases.extend((review_vtable_image(32, 'OwnedClass', review_kind), b'', False) for review_kind in ['ret', 'no-call'])
    review_comparisons = 0
    with tempfile.TemporaryDirectory(prefix='owned-derivative-check-') as review_temp:
        review_work = Path(review_temp)
        for review_level in ['O0', 'O2']:
            review_old = review_work / ('upstream-' + review_level)
            review_new = review_work / ('rewritten-' + review_level)
            subprocess.run(['clang', '-std=c99', '-' + review_level, str(review_options.reference.resolve()), '-o', str(review_old)], check=True)
            subprocess.run(['clang', '-std=c99', '-' + review_level] + [str(review_path) for review_path in sorted((review_root / 'Sources').glob('*.c'))] + ['-o', str(review_new)], check=True)
            for review_index, (review_fixture, review_input, review_noargs) in enumerate(review_cases):
                review_left = review_run(review_old, review_fixture, review_input, review_work / ('left-' + review_level + '-' + str(review_index)), review_noargs)
                review_right = review_run(review_new, review_fixture, review_input, review_work / ('right-' + review_level + '-' + str(review_index)), review_noargs)
                assert review_left == review_right, (review_level, review_index, review_left, review_right)
                assert review_left[0] == 0, (review_level, review_index, review_left)
                if review_project == 'VTableBrook' and 5 <= review_index < 95:
                    assert b'Name: OwnedClass' in review_left[1] and b'vtable: 0xffff000000003400' in review_left[1]
                review_comparisons += 1
    review_result = {'status': 'PASS', 'project': review_project, 'process_and_output_comparisons': review_comparisons,
                     'optimization_levels': ['O0', 'O2'], 'fixture_inputs': len(review_cases),
                     'reference_sha256': hashlib.sha256(review_options.reference.read_bytes()).hexdigest(),
                     'scope': 'Owned synthetic Mach-O fixtures, output bytes, exit status and extracted-file bytes; no live-device validation.'}
    if review_options.output:
        review_options.output.write_text(json.dumps(review_result, indent=2) + '\n')
    print(json.dumps(review_result))

if __name__ == '__main__':
    review_main()

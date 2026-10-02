# Historical v1.0.0 verification. See vtablebrook_safety.py for the current rewrite.
"""Compare executable Clang AST bodies after undoing implementation renames."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

def review_main():
    review_parser = argparse.ArgumentParser()
    review_parser.add_argument('--reference', type=Path, required=True)
    review_parser.add_argument('--output', type=Path)
    review_args = review_parser.parse_args()
    review_root = Path(__file__).resolve().parents[1]
    review_map = json.loads((review_root / 'RENAME_MAP.json').read_text())
    assert hashlib.sha256(review_args.reference.read_bytes()).hexdigest() == review_map['reference_source_sha256'], 'Reference bytes must match the pinned upstream source.'
    review_inverse = {review_row['new']: review_row['old'] for review_row in review_map['definitions']}
    review_ignored = {'id', 'loc', 'range', 'previousDecl', 'referencedMemberDecl', 'mangledName',
                      'isReferenced', 'isUsed', 'storageClass', 'parentDeclContextId'}

    def review_normalize(review_node):
        if isinstance(review_node, list):
            return [review_normalize(review_child) for review_child in review_node]
        if isinstance(review_node, dict):
            return {review_key: review_normalize(review_value) for review_key, review_value in review_node.items()
                    if review_key not in review_ignored and not review_key.endswith('DeclId')}
        if isinstance(review_node, str):
            return re.sub(r'\b[A-Za-z_]\w*\b', lambda review_match: review_inverse.get(review_match.group(), review_match.group()), review_node)
        return review_node

    def review_bodies(review_file):
        review_ast = json.loads(subprocess.check_output(['clang', '-Xclang', '-ast-dump=json', '-fsyntax-only', str(review_file)], text=True))
        review_results = {}
        for review_node in review_ast['inner']:
            if review_node.get('kind') == 'FunctionDecl':
                review_compound = next((review_child for review_child in review_node.get('inner', [])
                                        if review_child.get('kind') == 'CompoundStmt'), None)
                if review_compound is not None:
                    review_name = review_inverse.get(review_node['name'], review_node['name'])
                    review_results[review_name] = review_normalize(review_compound)
        return review_results

    review_expected = review_bodies(review_args.reference)
    review_expected = {review_name: review_body for review_name, review_body in review_expected.items()
                       if review_name == 'main' or review_name in review_inverse.values()}
    review_actual = {}
    for review_file in (review_root / 'Sources').glob('*.c'):
        for review_name, review_body in review_bodies(review_file).items():
            if review_name in review_expected:
                if review_name in review_actual:
                    assert review_actual[review_name] == review_body
                review_actual[review_name] = review_body
    review_missing = sorted(set(review_expected) - set(review_actual))
    review_differences = [review_name for review_name in review_expected
                          if review_name in review_actual and review_expected[review_name] != review_actual[review_name]]
    review_result = {'status': 'PASS' if not review_missing and not review_differences else 'FAIL',
                     'project': review_map['project'], 'functions_matched': len(review_expected) - len(review_missing) - len(review_differences),
                     'missing': review_missing, 'differences': review_differences,
                     'normalization': 'Implementation identifier maps, source locations and compiler-memory declaration identities; file-local to modular linkage is intentional.'}
    if review_args.output:
        review_args.output.write_text(json.dumps(review_result, indent=2) + '\n')
    print(json.dumps(review_result))
    assert review_result['status'] == 'PASS'

if __name__ == '__main__':
    review_main()

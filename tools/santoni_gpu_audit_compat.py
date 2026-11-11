"""Prove unchanged shared decoder code when only kernel audit orchestration grows."""
import ast
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
# This committed version is the exact dependency of the retained EL0 evidence.
PRE_LAUNCHER = '481d5db04d2f9d1800995de0a7da8b6c18b917bd'
# The independently completed 0211 traced probe used this exact auditor source.
# Admit its orchestration-only successors through the same unchanged-AST rule.
TRACE_PROBE = '047d3025d1c3d184ecc5dc5ce4f88ce68a730c98'
KERNEL_AUDITOR = 'tools/check_santoni_gpu_kernel.py'


def shared_ast(source):
    tree = ast.parse(source)
    audits = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'audit']
    if len(audits) != 1:
        raise ValueError('kernel audit orchestration missing or ambiguous')
    tree.body = [n for n in tree.body if n is not audits[0]]
    return ast.dump(tree)


def kernel_auditor_compatible(previous_hash):
    for revision in (PRE_LAUNCHER, TRACE_PROBE):
        old = subprocess.check_output(['git', 'show', revision + ':' + KERNEL_AUDITOR], cwd=ROOT)
        if hashlib.sha256(old).hexdigest() == previous_hash:
            return shared_ast(old) == shared_ast((ROOT / KERNEL_AUDITOR).read_bytes())
    return False

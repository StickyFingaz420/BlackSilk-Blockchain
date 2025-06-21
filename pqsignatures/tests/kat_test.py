# KAT test harness for pqsignatures
# Place JSON KAT files in tests/kat/
# Each KAT file should have fields: message, public_key, secret_key, signature

import os
import json
import glob
import subprocess

KAT_DIR = os.path.join(os.path.dirname(__file__), 'kat')

SCHEMES = [
    ('dilithium2', 'dilithium2_kat.json'),
    ('falcon512', 'falcon512_kat.json'),
    ('mldsa44', 'mldsa44_kat.json'),
]

def run_kat(scheme, kat_file):
    with open(os.path.join(KAT_DIR, kat_file), 'r') as f:
        vectors = json.load(f)
    for v in vectors:
        msg = bytes.fromhex(v['message'])
        pk = bytes.fromhex(v['public_key'])
        sk = bytes.fromhex(v['secret_key'])
        sig = bytes.fromhex(v['signature'])
        # Call Rust test binary with args
        result = subprocess.run([
            'cargo', 'run', '--release', '--bin', f'kat_{scheme}',
            msg.hex(), pk.hex(), sk.hex(), sig.hex()
        ], capture_output=True, text=True)
        assert 'KAT OK' in result.stdout, f"KAT failed for {scheme}: {result.stdout}"

if __name__ == '__main__':
    for scheme, kat_file in SCHEMES:
        run_kat(scheme, kat_file)

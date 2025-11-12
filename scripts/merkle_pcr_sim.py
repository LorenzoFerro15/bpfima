import argparse
import hashlib
import subprocess
import sys
import re
from typing import List

MERKLE_HASH_SIZE = 32


def parse_hex_line(s: str) -> bytes:
    s = s.strip().lower()
    if s.startswith('0x'):
        s = s[2:]
    s = ''.join(ch for ch in s if ch in '0123456789abcdef')
    if len(s) % 2:
        s = '0' + s
    return bytes.fromhex(s)


def read_history(path: str) -> List[bytes]:
    entries = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            b = parse_hex_line(line)
            if len(b) != MERKLE_HASH_SIZE:
                raise SystemExit(f'Invalid entry length {len(b)} != {MERKLE_HASH_SIZE} in {path}')
            entries.append(b)
    return entries


def compute_merkle_root(history: List[bytes], start_root: bytes | None = None) -> bytes:
    root = start_root if start_root is not None else b'\x00' * MERKLE_HASH_SIZE
    for leaf in history:
        h = hashlib.sha256()
        h.update(root)
        h.update(leaf)
        root = h.digest()
    return root


def compute_simulated_pcr(history: List[bytes], start_root: bytes | None = None) -> bytes:
    root = start_root if start_root is not None else b'\x00' * MERKLE_HASH_SIZE
    pcr = b'\x00' * MERKLE_HASH_SIZE
    for leaf in history:
        h = hashlib.sha256()
        h.update(root)
        h.update(leaf)
        root = h.digest()

        hp = hashlib.sha256()
        hp.update(pcr)
        hp.update(root)
        pcr = hp.digest()
    return pcr


def read_pcr_from_tpm() -> bytes:
    try:
        p = subprocess.run(['sudo', 'tpm2_pcrread', 'sha256:23'], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise SystemExit('tpm2_pcrread not found; install tpm2-tools or adjust PATH')
    if p.returncode != 0:
        raise SystemExit(f'tpm2_pcrread failed: {p.stderr.strip()}')
    out = p.stdout
    candidate = None
    for line in out.splitlines():
        token = line.split(': ', 1)[-1].strip() if ': ' in line else line.strip()
        token = ''.join(token.split())
        if token.lower().startswith('0x'):
            token = token[2:]
        if re.fullmatch(r'[0-9a-fA-F]+', token):
            candidate = token
            break
    if not candidate:
        raise SystemExit('Could not parse PCR value from tpm2_pcrread output')
    b = bytes.fromhex(candidate)
    if len(b) != MERKLE_HASH_SIZE:
        raise SystemExit('PCR length mismatch')
    return b


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--history', required=True)
    p.add_argument('--pcr-from-tpm', action='store_true')
    p.add_argument('--pcr', help='Provide PCR hex directly (optional)')
    args = p.parse_args()

    history = read_history(args.history)

    if args.pcr_from_tpm:
        pcr = read_pcr_from_tpm()
    elif args.pcr:
        token = re.sub(r'[^0-9a-fA-F]', '', args.pcr.strip())
        pcr = bytes.fromhex(token)
    else:
        raise SystemExit('Either --pcr-from-tpm or --pcr must be provided')

    merkle_root = compute_merkle_root(history)
    simulated_pcr = compute_simulated_pcr(history)

    print('Computed merkle root :', merkle_root.hex())
    print('Simulated TPM PCR    :', simulated_pcr.hex())
    print('Provided PCR         :', pcr.hex())

    if simulated_pcr == pcr:
        print('\nMATCH: simulated PCR == provided PCR')
        return 0
    if merkle_root == pcr:
        print('\nMATCH: merkle root == provided PCR')
        return 0
    print('\nMISMATCH')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())


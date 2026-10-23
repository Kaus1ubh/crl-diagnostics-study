"""Reproduce the supplementary G1 signing-key check offline, without changing the benchmark."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import analyze
import benchmark_checks as check

HERE = Path(__file__).resolve().parent
FOLLOWUP = HERE / 'followups' / 'g1-ocsp'


def reproduce():
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('OpenSSL required')
    manifest = json.loads((FOLLOWUP / 'manifest.json').read_text(encoding='utf-8'))
    inputs = {}
    for name, item in manifest['inputs'].items():
        path = (HERE / item['file']).resolve()
        if not path.is_relative_to(HERE) or analyze.sha(path.read_bytes()) != item['sha256']:
            raise ValueError(f'Input hash or path mismatch: {name}')
        inputs[name] = path.read_bytes()
    results = {}
    with tempfile.TemporaryDirectory() as folder:
        work = Path(folder)
        for crl in ('crl11', 'crl12'):
            for cert in ('stated_issuer', 'ocsp_signer'):
                results[f'{crl}_{cert}'] = check.check_pair(openssl, inputs[crl], inputs[cert], work)
        # A changed signature must not pass under the candidate public key.
        modified = bytearray(inputs['crl11'])
        modified[-1] ^= 1
        results['altered_signature_ocsp_signer'] = check.check_pair(
            openssl, bytes(modified), inputs['ocsp_signer'], work)
    expected = {
        'crl11_stated_issuer': 'fail', 'crl11_ocsp_signer': 'pass',
        'crl12_stated_issuer': 'pass', 'crl12_ocsp_signer': 'fail',
        'altered_signature_ocsp_signer': 'fail',
    }
    for name, outcome in expected.items():
        if results[name]['checks']['raw_signature'] != outcome:
            raise AssertionError(f'Unexpected raw signature result: {name}')
    candidate = results['crl11_ocsp_signer']['checks']
    if candidate['issuer_name'] != 'fail' or candidate['openssl_crl'] != 'fail':
        raise AssertionError('Candidate verification must not imply normal CRL validation')
    return {
        'recorded_at': datetime.now(timezone.utc).isoformat(),
        'openssl': subprocess.check_output([openssl, 'version'], text=True).strip(),
        'manifest_sha256': analyze.sha((FOLLOWUP / 'manifest.json').read_bytes()),
        'results': results,
    }


if __name__ == '__main__':
    result = reproduce()
    (FOLLOWUP / 'results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    for name, row in result['results'].items():
        print(f"{name}: raw={row['checks']['raw_signature']}, normal={row['checks']['openssl_crl']}")

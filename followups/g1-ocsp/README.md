# G1 CRL #11: an OCSP signing key

On 23 October 2026, I reproduced [Zihao Wang's identification](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c34)
of the public key that verifies eMudhra G1 CRL #11. Wang published the finding
on 22 October. [Wayne subsequently noted](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c36)
that the key was already known in the original investigation. Discovery credit
belongs to them; this follow-up preserves a reproducible copy.

## Result

| Frozen CRL | Stated root public key | OCSP public key |
| --- | --- | --- |
| #11 | Raw signature fails | Raw signature verifies |
| #12 | Raw signature verifies | Raw signature fails |

Flipping one bit of #11's signature also fails under the OCSP key. The
original CRLs, signed contents and signatures are otherwise unchanged.

The matching certificate's subject is `EMSIGN ROOT TLS CA - G1 OCSP 2026 - 4`.
It has Digital Signature key usage and OCSP Signing extended key usage. It
does not grant CRL signing usage. Its subject and key identifier differ from
those declared in the CRL, and normal OpenSSL CRL verification still fails.
The raw signature match identifies a corresponding signing key; it does not
establish valid CRL issuance, explain how the key was selected, or prove that
the private key was compromised.

## Reproduce offline

From the repository root, with Python 3.12+ and OpenSSL 3 on PATH:

```sh
python run_g1_followup.py
```

The runner checks all four input hashes, tests both CRLs against both public
keys, and tests an altered signature. It asserts the expected results and
overwrites `results.json` with commands, outputs and engine version. It makes
no network requests. The original `benchmark/cases.json` and benchmark results
are unchanged.

## Certificate source

The crt.sh endpoint in Wang's comment was unreachable during this reproduction.
I retrieved the same named certificate from the Sectigo Statue2027h2 log entry
linked in his comment: index **1172**. I parsed the `x509_entry` from data tile
4, entry offset 148, using the [Static CT API format](https://c2sp.org/static-ct-api@v1.1.0).

- Certificate SHA-256: `9B43AA54CD6971C1432A1CCA607D3D79D7B9128959D5AB7B796B2BF7F45450BF`
- Frozen CRL #11 SHA-256: `9846BF9A4F213D8FBA87E79D464732B9CC35A784F7992334EC3BC6DB2A6F7DBD`
- Certificate validity: 14 October 2026, 07:30:30 UTC to 13 October 2027, 07:30:30 UTC.

`manifest.json` records source URLs, acquisition time and hashes. The source
checkpoint is retained as acquisition metadata. I did not verify its signature
or a Merkle inclusion proof; this is an HTTPS retrieval and independent CRL
signature reproduction, not a CT-log audit. Only the extracted public
certificate is needed for the offline check.

---
description: "Results and limits of five diagnostic checks on 19 historical CRLs and three synthetic controls"
type: research
status: active
aliases: [CRL diagnostic benchmark results]
---
# CRL diagnostic benchmark, 22 October 2026

Five categorical checks distinguish six metadata-related failures in this
retrospective collection. Seven historical signatures remain unresolved by
those checks. Six historical CRLs pass all five checks. None of these findings
establishes full CRL conformance or predicts later CA compromise.

## Method and results

The frozen [protocol](BENCHMARK_PROTOCOL.md) defines exact DER issuer-name
comparison, AKI/SKI comparison, limited algorithm consistency, raw signature
verification and normal OpenSSL CRL verification with a stated issuer.
Issuer selection follows source context; incident annotations do not enter the
classifier. Duplicate complete CRL bytes are collapsed while retaining aliases.
The collection contains five incident groups across four operators. Cases from
one incident are correlated and must not be treated as independent trials.

| Historical group | Distinct CRLs | Name mismatch, raw pass | Algorithm-family mismatch, raw pass | Unresolved signature failure | All five pass |
| --- | ---: | ---: | ---: | ---: | ---: |
| eMudhra May 2025 | 5 | 0 | 0 | 5 | 0 |
| eMudhra G1 October 2026 | 2 | 0 | 0 | 1 | 1 |
| GlobalSign 2022 | 1 | 0 | 1 | 0 | 0 |
| GlobalTrust 2024 | 10 | 5 | 0 | 0 | 5 |
| iTrusChina 2021 | 1 | 0 | 0 | 1 | 0 |
| Total | 19 | 5 | 1 | 7 | 6 |

No basic check returned unknown in the recorded run. The full engine version,
commands, outputs, artifact hashes, code hashes and source annotations are in
[results/benchmark.json](results/benchmark.json). A compact row-level view is
[results/benchmark.csv](results/benchmark.csv).

GlobalSign's declared RSA signature family mismatches its EC issuer key.
The original raw signature nevertheless verifies with that EC public key and
SHA-256. Inner and outer identifiers match each other, so equality alone would
miss this particular inconsistency. A diagnostic raw pass does not make the
original algorithm declaration valid.

Five individual GlobalTrust attachments have issuer names ordered differently
from their certificate subjects. Their raw signatures verify, but normal
OpenSSL CRL verification fails issuer lookup. Five other CRLs in the supplied
ZIP have matching names and pass the five checks. Exact DER comparison is the
specified measurement, not a universal semantic DN comparison.

The eMudhra failure cases pass the three metadata checks but fail both signature
checks with their stated issuer keys. These observations do not identify an
actual signer or prove key compromise. Six May 2025 attachment occurrences are
only five distinct objects; the duplicated attachment does not supply a sixth
independent case.

## Supplementary evidence

### G1 CRL #11 follow-up, 23 October 2026

After the frozen run, I reproduced [Zihao Wang's public finding in comment 34](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c34).
The signature on our exact G1 CRL #11 verifies with the public key of
`EMSIGN ROOT TLS CA - G1 OCSP 2026 - 4`. CRL #12 fails under that key and
verifies under the stated root key. This identifies a matching signing key
for one of the seven failures left unresolved by the original five checks.
Normal CRL verification still fails with the OCSP certificate; a matching
raw signature does not establish an authorised CRL signer.

[The follow-up](followups/g1-ocsp/README.md) preserves the additional public
certificate, provenance, hashes, verification outputs and negative control.
Wang supplied the public identification and commands. Wayne's [comment 36](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c36)
says the signing-key answer was already known in the original investigation.
This is a reproduction of their work. The original table and pairings above
remain the frozen benchmark, not a claim that this case is still unexplained.

### iTrusChina alternate payload

iTrusChina supplied an alternate 117-byte TBSCertList in addition to the
published 167-byte signed contents. The original signature verifies over that
alternate payload and fails over the published payload. This reproduces the
operator's reported signed-payload mismatch. The extra bytes make that
explanation testable; the five basic checks alone leave it unresolved.

Three local synthetic controls are counted separately. One normally signed RSA
CRL passes all five checks. One CRL signed by a different key, and another
modified after signing, both yield pass/pass/pass/fail/fail. Supplementary
verification with the supplied alternate key or original payload respectively
resolves their constructed causes. Private signing keys are not retained.

This demonstrates ambiguity in the five categorical outcomes only. Full RSA
diagnostics differed: the wrong-key control produced padding failures, while
the changed-payload control produced a bad-signature error. These richer
observations may be useful. The benchmark does not establish a general
impossibility result or validate an error-message root-cause classifier.

## Scope and prior work

This is a convenience sample selected retrospectively. The protocol preceded
the consolidated run, but the historical data had already been inspected.
No blindness, preregistration, general accuracy, prevalence or significance is
claimed. Algorithm consistency omits parameter and policy checks; the benchmark
also omits time, scope, trust paths and revocation-content validation.

CRLite audit events are outside the 19-object benchmark. The three separately
studied cohorts contain 70,036 events. Their October 15 failed-verification
entries for eMudhra G1/G3 do not preserve the rejected bytes or their hashes.
They cannot establish the exact failing object or diagnose its cause.
The ORC archive is also excluded: its objects have not received the curated
issuer pairing and verification applied here.

Existing [x509-limbo CRL cases](https://x509-limbo.com/testcases/crl/) already
exercise invalid signatures and wrong signing keys. Inspection of
[pkilint's CRL validator at commit 820a614](https://github.com/digicert/pkilint/blob/820a6146e255205b8b633de3e36856f011a628e3/pkilint/pkix/crl/crl_validator.py)
found an existing inner/outer signature-algorithm equality check. This was a
source review, not an execution comparison against those tools. No new
upstream gap is established, so no duplicate issue or PR was opened.

The result is a reproducible diagnostic case collection with explicit limits.
Original incident investigators retain discovery credit. Sources and collection
details are in [SOURCES.md](SOURCES.md), [FEASIBILITY.md](FEASIBILITY.md) and
[DATA_EXPANSION.md](DATA_EXPANSION.md).

## Reproduction

Python 3.12+ and OpenSSL 3 are required. With the frozen files present:

```sh
python run_benchmark.py
python -m unittest discover -s . -p test_benchmark.py -v
```

This run needs no network or original archive extraction. The manifests and
content-addressed benchmark artifacts preserve provenance. The separate
collection scripts reproduce the wider evidence audit. OpenSSL diagnostic
wording can differ between releases; the recorded engine and raw outputs
are retained for comparison.

# CRL diagnostics study

I collected **19 distinct historical certificate revocation lists (CRLs)** from
five incident groups across four operators. I added three synthetic controls
to test what five diagnostic checks can tell us about a failure.

The checks distinguish some issuer-name and algorithm errors. Seven historical
signatures remain unresolved. I wrote up the cases in
[What a broken CRL can tell you](https://kaustu.bh/blog/what-a-broken-crl-can-tell-you).

## Run offline

Requires Python 3.12+ and OpenSSL 3 on PATH. The runner uses Python's standard
library and the included fixtures. It runs offline.

```sh
git clone https://github.com/Kaus1ubh/crl-diagnostics-study.git
cd crl-diagnostics-study
python run_benchmark.py
python -m unittest discover -s . -p test_benchmark.py -v
```

The runner verifies the protocol and fixture hashes, then overwrites
`results/benchmark.json` and `results/benchmark.csv`. The committed results were
recorded with OpenSSL 3.6.3. Your run will have a new timestamp; the engine version
and diagnostic wording may also differ.

## Historical results

| Historical result | Distinct CRLs |
| --- | ---: |
| Verified raw signature with issuer-name mismatch | 5 |
| Verified raw signature with signature-family/key-family mismatch | 1 |
| Unresolved signature failure under the five checks | 7 |
| No failure in the five checks | 6 |
| Total | 19 |

I chose each issuer certificate from the source material before running the
checks. They compare issuer DER bytes, AKI/SKI, limited algorithm consistency,
the original raw signature and normal OpenSSL CRL verification.

The wrong-key and changed-payload controls produce identical five-check results.
Their detailed RSA errors differ, so the ambiguity applies only to that summary.
For iTrusChina, the operator supplied an alternate signed payload. The original
signature verifies over those bytes, which helps establish the cause.

The [report](BENCHMARK_REPORT.md) explains each incident group. The
[protocol](BENCHMARK_PROTOCOL.md) defines the checks. Incident-report annotations
are kept separate from computed diagnoses.

## Limits

- I inspected the cases before fixing the protocol. The sample cannot estimate
  accuracy, prevalence or the probability of later compromise. Cases within an
  incident group are correlated.
- Issuer names are compared by exact bytes. Algorithm checks omit parameter
  and policy requirements. Time validity, CRL scope and certificate-path trust
  are outside scope; expiry of a synthetic certificate does not affect these checks.
- A failed signature alone does not establish the signer or key compromise.
  Passing the five checks does not establish full CRL conformance.
- I haven't found a new vulnerability or upstream test gap. Existing
  [x509-limbo cases](https://x509-limbo.com/testcases/crl/) cover invalid CRL
  signatures and wrong signing keys.

## Files and provenance

- `benchmark/cases.json` records the 22 CRL/issuer pairs and hashes.
- `benchmark/artifacts/` contains the exact bytes used by the runner.
- `benchmark/synthetic/` contains the public controls. Private keys were discarded.
- `benchmark_checks.py` implements the checks; `analyze.py` supplies DER and process helpers.
- [SOURCES.md](SOURCES.md) and [provenance.json](provenance.json) trace the artifacts to their sources.

`generate_benchmark_controls.py` shows how I made the controls. Without flags it
checks their hashes. `--new-snapshot` replaces them and changes the experiment.

`FEASIBILITY.md`, `DATA_EXPANSION.md` and the source manifests describe the wider
collection. Its raw downloads and collection scripts are outside this release.
The included fixtures are sufficient to reproduce the benchmark.

## Feedback

Please [open an issue](https://github.com/Kaus1ubh/crl-diagnostics-study/issues)
with the case ID, OpenSSL version, command/output and the conclusion you think
needs changing.

## License and credits

Original study code and writing are MIT licensed. Third-party incident artifacts
and source metadata are excluded from that grant; see
[THIRD_PARTY.md](THIRD_PARTY.md). Discovery credit remains with the original
incident reporters and investigators.

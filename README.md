# CRL diagnostics study

A reproducible retrospective study of **19 distinct historical certificate
revocation lists (CRLs)** from five incident groups across four operators, plus
three separately counted synthetic controls.

By [Kaustubh Singh](https://kaustu.bh). Read the accompanying article:
[What a broken CRL can tell you](https://kaustu.bh/blog/what-a-broken-crl-can-tell-you).

## Run offline

Requires Python 3.12+ and OpenSSL 3 on PATH. No Python packages, network access,
CA account, private keys or original archive extraction are required.

```sh
git clone https://github.com/Kaus1ubh/crl-diagnostics-study.git
cd crl-diagnostics-study
python run_benchmark.py
python -m unittest discover -s . -p test_benchmark.py -v
```

The runner verifies the protocol and fixture hashes, then writes
`results/benchmark.json` and `results/benchmark.csv`. A repeat run changes the
timestamp, engine version and possibly diagnostic wording. The committed outputs
record the original OpenSSL 3.6.3 run. The eight tests exercise the frozen input
hashes, controls, algorithm mismatch and treatment of tool errors.

These are signature diagnostics, not current-time trust decisions. The
synthetic certificates can expire without invalidating this experiment.

## What the checks establish

| Historical result | Distinct CRLs |
| --- | ---: |
| Verified raw signature with issuer-name mismatch | 5 |
| Verified raw signature with signature-family/key-family mismatch | 1 |
| Unresolved signature failure under the five checks | 7 |
| No failure in the five checks | 6 |
| Total | 19 |

The five checks compare issuer DER bytes, AKI/SKI, limited algorithm
consistency, the original raw signature and normal OpenSSL CRL verification.
The issuer certificate is stated in advance from source context.

A wrong-key synthetic control and a changed-payload synthetic control have
identical five-check categorical results. Their detailed RSA errors differ.
This demonstrates ambiguity in that summary, not indistinguishability of all
available evidence. Extra source artifacts can resolve a cause: the iTrusChina
signature verifies over the operator-supplied alternate signed payload.

Read [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md) for the incident-group results
and interpretation, and [BENCHMARK_PROTOCOL.md](BENCHMARK_PROTOCOL.md) for the
frozen definitions. Labels from incident reports are carried separately from
computed diagnoses.

## Limits

- Retrospective convenience sample; cases were inspected before the protocol
  was fixed. This is not a blinded evaluation or estimate of accuracy or prevalence.
- Five incident groups are correlated collections, not 19 independent trials.
- Strict issuer-name byte equality is not general semantic DN equivalence.
- Algorithm consistency is not a complete lint/profile check. Time validity,
  CRL scope, certificate-path trust and other requirements are outside scope.
- Failed verification does not establish an actual signer or key compromise.
  Passing these checks does not establish full conformance.
- No new vulnerability, early-warning predictor or novel upstream test gap is
  claimed. Existing x509-limbo cases already cover invalid CRL signatures and
  wrong signing keys.

## Files and provenance

- `benchmark/cases.json`: 22 frozen CRL/issuer pairs, hashes, incident groups,
  source aliases and supplementary-evidence references.
- `benchmark/artifacts/`: content-addressed CRLs, issuer certificates and
  supplementary signed bytes used by the runner.
- `benchmark/synthetic/`: three public controls and the alternate public key;
  private keys were discarded.
- `benchmark_checks.py`: the checks and classifier. `analyze.py` contains only
  shared hashing, subprocess and DER helpers extracted from the original study.
- `generate_benchmark_controls.py`: inspect the construction of the controls;
  running it without flags checks their hashes. `--new-snapshot` changes the
  synthetic files and is not reproduction of this frozen case set.
- [SOURCES.md](SOURCES.md) and [provenance.json](provenance.json): primary-source
  links and artifact origins. The original source manifests are retained in
  `evidence/manifest.json` and `expansion/manifest.json`.
- `FEASIBILITY.md` and `DATA_EXPANSION.md`: collection-phase background reports.
  Their wider raw downloads and collection scripts are outside this focused release.

The source manifests describe a larger collection than the files included here.
Their hashes in the case manifest preserve the collection context; reproduction
uses the content-addressed benchmark fixtures directly.

## Feedback

Please [open an issue](https://github.com/Kaus1ubh/crl-diagnostics-study/issues)
with the case ID, OpenSSL version, command/output and the specific conclusion
you think needs changing. Corrections to issuer pairing, source interpretation,
algorithm handling and the limits of the synthetic controls are especially useful.

## License and credits

Original study code and writing are MIT licensed. Third-party incident artifacts
and source metadata are excluded from that grant; see
[THIRD_PARTY.md](THIRD_PARTY.md). Discovery credit remains with the original
incident reporters and investigators.

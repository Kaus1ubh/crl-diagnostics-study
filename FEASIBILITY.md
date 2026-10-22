---
description: "What preserved CRLs establish, what they cannot establish, and whether to continue"
type: research
status: active
aliases: [CRL research verdict]
---

> Collection-phase background note. This repository publishes the frozen
> benchmark subset. Wider collection scripts and raw archives referenced below
> are outside this release; use README.md to reproduce the included cases.

# Feasibility: CRL signatures as evidence of CA key-management failures

This records the initial sample. The subsequent [data expansion](DATA_EXPANSION.md)
adds two independently verified failure mechanisms and public audit cohorts.
Use that report for the updated evidence-availability assessment.

Investigated 22 October 2026. The useful question is how to diagnose a signature
failure and decide what evidence resolves it. The available sample does not
justify a model predicting future private-key compromise.

## Evidence and measurements

Archived 22 source files with SHA-256 provenance: three incident records and
their comments/attachment metadata, CRL attachments, public certificates, a
historical dashboard response and a targeted archive-index response. All are
public sources. The issuer arrays reuse the byte-identical 22 October reference
snapshot from the earlier study; no other users' data was collected.

The experiment evaluated nine CRL file occurrences, eight distinct CRL byte
sequences. Each raw signature was tested against 14 distinct public keys, for
126 checks. Those keys are represented by 23 certificates, including cross-signs.
This is a small selected candidate set, not a complete CCADB search.

| Preserved sample | Distinct CRLs | Metadata | Raw signature finding |
|---|---:|---|---|
| eMudhra May 2025 attachments | 5 across 6 attachments | Subject/issuer names and AKI/SKI match corresponding published issuer certificates | None verifies under the corresponding key or another key in the selected candidate set |
| eMudhra G1 CRL 11, October 2026 | 1 | Issuer name and AKI match the supplied root and cross-certificate | Does not verify under their shared key or another selected candidate key |
| eMudhra G1 CRL 12, October 2026 | 1 | Issuer name and AKI match the same supplied certificates | Verifies under the supplied G1 public key |
| GlobalSign October 2022 attachment | 1 | AKI matches an EC issuer, but the CRL declares an RSA signature algorithm | Original signed bytes verify under the EC issuer key with SHA-256; normal CRL verification fails |

The two successful original-artifact checks exercise RSA and ECDSA verification.
An additional altered-signature test fails as expected. Eight automated tests
pass, including evidence hashes, truncated DER, duplicate counting and dashboard
row association. Raw outputs are in [analysis.json](results/analysis.json).

The GlobalSign issuer was fetched from its public CA repository; its SHA-256
certificate fingerprint is independently consistent with the fingerprint in the
original incident report:
`65EEC0CC6C970CC1CD73659115DC8D904E6F12E6DC8FD4DDA39D54CB30224780`.

## What the historical record establishes

The June 3, 2025 Internet Archive capture of crt.sh's disclosure dashboard
contains twelve certificate/error pairs for the six affected TLS CA subjects.
They include direct and cross-signed certificate variants, so they are not
twelve independent CA-key failures. Each paired error explicitly reports an
ECDSA verification failure for the subject's CRL URL.

The dashboard's “Listed Here Since” column shows May 23, 2025. That is evidence
about the displayed record, not by itself cryptographic evidence of the exact
onset of this particular error. The preserved snapshot establishes that the
failure was visible by the June 3 capture. Mozilla had already identified and
linked this archive in the current incident's comment 5; finding this relationship
is not our discovery.

The six attachments from the earlier incident are not six independent CRLs:
attachments 9493661 and 9493663 are byte-identical and name EM EV TLS CA - G3B.
The attachment set covers five actual issuer subjects; it contains no separate
EM DV TLS CA - G3B CRL. The dashboard supplies historical monitoring evidence
for that sixth subject, but not its original CRL bytes in our collected sample.

The historical incident report says the CRLs were signed using incorrect key
configuration. In current comment 11, eMudhra states they originally used the
intended keys and subsequently re-signed with the flawed keys to match the
published CA certificates. Those are the operator's accounts. Our failed
signature checks independently establish non-verification under the selected
public keys; they do not establish the identity, strength, or generation path
of the actual unknown signing keys.

## Why simple failure detection is not the research contribution

1. **Detection already existed.** The preserved dashboard shows the failures,
   and the earlier incident was opened in response. A new generic CRL monitor
   would repeat an existing capability.
2. **Matching identifiers do not prove key correspondence.** All supplied
   May-2025 samples have matching AKI/SKI values despite failing signature
   checks. Names and key identifiers can accompany a signature made using a
   different key or an otherwise invalid signature.
3. **Failure does not imply a compromised private key.** The GlobalSign case
   is a concrete alternative mechanism: the raw signature works, while the
   declared algorithm is incompatible with the issuer's key type. This is not
   evidence of private-key recovery or compromise.
4. **Repairing verification does not prove sound key provenance.** The current
   eMudhra account describes making CRLs verify by switching to the key matching
   the certificate. Assessing the safety of that key requires separate evidence.

The fourth point is a motivation for research, not a new causal conclusion
drawn from the bytes alone.

## Limits on a predictive study

There is one selected compromised-key incident and one algorithm-mislabeling
comparison, plus one additional G1 failure from the same operator. They do not
provide a representative denominator, independent outcomes, or sufficient
negative cases. We cannot estimate precision, false-positive rate, recall,
population prevalence, or predictive warning time from this sample.

A targeted Wayback index request for the EV G3B CRL over April–July 2025 returned
no captures. That result applies only to that query and interval. It does not
prove that all historical CRLs are unavailable. The dashboard capture is not a
substitute for repeated raw CRL snapshots.

Prior research already studied longitudinal revocation data and the difficulty
of preserving revocation history. Our source review is a feasibility search,
not an exhaustive literature review or a novelty certification.

## Decision and a bounded next experiment

**Proceed with a narrowly framed diagnostic case study; do not claim a predictor
of key compromise or start a new monitoring product on this evidence.**

The strongest experimental follow-up is controlled key-workflow fault injection:

- Keep two locally generated test keys representing the intended key and the
  key accidentally selected for a CSR. Publish a test certificate for the latter.
- Generate a CRL using the intended key but copy identifiers corresponding to
  the published certificate; demonstrate the metadata/signature discrepancy.
- Re-sign using the certified key and compare the checks that now pass with
  the independent key-provenance checks still missing.
- Compare safeguards: identifier comparison, post-signature verification,
  public-key binding against the ceremony record, and a bounded weak-key test.

Use synthetic keys and a software model; do not infer actual HSM behavior or
claim this recreates an undisclosed production implementation. First check prior
work and available PKCS#11/HSM testing projects for an existing equivalent.

This experiment would test what different safeguards detect under an explicit
fault model. Its usefulness depends on finding a coverage gap or an actionable
upstream regression test; generating an expected demonstration alone is not
enough to justify a new tool or a strong publication claim. It has not been run
as part of this feasibility audit.

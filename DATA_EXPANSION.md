---
description: "Expanded CRL evidence: incident corpus, verified failure mechanisms and public audit cohorts"
type: research
status: active
aliases: [CRL additional data, CRL dataset expansion]
---

> Collection-phase background note. This repository publishes the frozen
> benchmark subset. Wider collection scripts and raw archives referenced below
> are outside this release; use README.md to reproduce the included cases.

# Additional data found and verified

Collected 22 October 2026. The initial three-case feasibility search was too
narrow to establish how much usable evidence exists. The expanded collection
adds verifiable mechanisms and a public source of cross-issuer observations.
It still does not establish that CRL failures predict private-key compromise.

## Collection inventory

| Source | Retrieved | What it supports |
|---|---|---|
| Mozilla CA-compliance incident search | 170 report records; comments and attachment metadata for 14 additional selected reports | A reproducible incident-discovery frame and leads across multiple operators |
| iTrusChina 2021 attachment | Broken CRL, issuer certificate, two supplied signed-payload variants | Independent verification that the signature covers different bytes from the published CRL |
| GlobalTrust 2024 attachments | Ten distinct CRLs, three issuer certificates including one in the supplied ZIP | Raw signature versus issuer-name checks across several dates |
| Mozilla CRLite production audits | Three snapshots; 70,036 audit records; union of 1,851 issuer identifiers and 20,111 URL strings | Public cross-issuer collection telemetry before, during and after the October eMudhra CRL failures |
| ORC historical archive | 2,588 file occurrences, 2,587 distinct file hashes; 2.43 MB uncompressed | Additional longitudinal signed-artifact candidate corpus, kept separate from the WebPKI incident sample |

The expansion cache contains **50 source files** with exact URLs, byte sizes and
SHA-256 hashes in `expansion/manifest.json`. The three large CRLite audits are
cached locally and excluded from Git; generation-pinned download URLs reproduce
them. All other source files and derived summaries are committed locally.

The original eight distinct incident CRLs plus eleven new ones yield **19
distinct incident CRLs with signature-test results**, spanning eMudhra,
GlobalSign, iTrusChina and e-commerce monitoring GmbH / GlobalTrust. Multiple CRLs
from one issuer or incident are repeated observations, not independent incidents.
The ORC archive is not merged into that count and has not had its signatures
verified against issuer certificates.

## Verified new mechanism: signature covers the wrong payload

[Bug 1712664](https://bugzilla.mozilla.org/show_bug.cgi?id=1712664), reported in
2021, preserves an attachment containing `Wrong ARL.crl`, `RSA Root.cer`, and two
hex-encoded TBSCertList payloads. The offline reproduction establishes:

- The TBSCertList extracted from the published CRL is **167 bytes** and exactly
  equals the supplied complete payload.
- The CRL's original RSA/SHA-256 signature does **not** verify over those bytes.
- That same signature **does** verify under the supplied issuer certificate
  over the supplied **117-byte** payload, which omits the extensions.

This is direct evidence of a mismatch between the signed payload and the
published payload. The operator's report had already described an assembly bug;
our contribution here is a checked reproduction, not its discovery. It provides
a concrete alternative to a wrong signing key as an explanation of a failed
CRL signature.

## Verified comparison: correct signature, wrong issuer name

[Bug 1888371](https://bugzilla.mozilla.org/show_bug.cgi?id=1888371) preserves
CRLs from March, April and June 2024 plus operator-supplied April examples.
Current public issuer certificates were retrieved from the operator's repository.

All **ten** supplied CRL signatures verify under the corresponding public keys.
However, the **five individually attached CRLs** fail OpenSSL CRL issuer lookup;
their issuer names differ in ordering from the corresponding certificate
subjects. The **five CRLs in the operator-supplied ZIP** pass the same check.

That distinction is visible in `results/expansion-summary.json`: raw signature
verification and normal CRL verification are recorded separately. The report
and attachments already described the naming problem. These are historical
comparison artifacts, not evidence that the operator currently serves them.
No claim is made that a passing OpenSSL signature check is a complete RFC/profile
or certificate-path validation.

## Public cohort source: Mozilla CRLite audit logs

Mozilla documents its public production bucket in the
[CRLite wiki](https://github.com/mozilla/crlite/wiki#where-can-i-get-the-crlite-data-that-is-used-to-make-filters).
The live repository describes the
[CRL collection pipeline](https://github.com/mozilla/crlite).
Public storage API listing and object retrieval worked without authentication.
The October-prefix listing returned 44 run prefixes; three audits were sampled:

| Snapshot | Audit records | Distinct issuer identifiers | Distinct URLs | `Failed Verify` records |
|---|---:|---:|---:|---:|
| 20261014-0 | 23,328 | 1,847 | 20,076 | 0 |
| 20261015-0 | 23,353 | 1,850 | 20,099 | 2 |
| 20261018-0 | 23,355 | 1,839 | 20,099 | 0 |

These are **audit events**, not unique certificates, unique downloads, or
independent CA failures. An issuer/URL can have multiple events in a run.
`Wrong distribution point`, `Not Fresh, Warning`, and other labels are collector
diagnostics, not automatic findings of a security incident or private-key
compromise. The audits do not by themselves provide a population outcome label.

The October 15 audit records:

- `2026-10-15T01:00:42.962736238Z`: RSA signature verification failure for
  `http://crl.emsign.com?roottlscag1.crl`.
- `2026-10-15T01:01:33.634244753Z`: ECDSA signature verification failure for
  `http://crl.emsign.com?roottlscag3.crl`.

The same run later records `Valid, Processed` for those issuer/URL pairs, using
the **same successful CRL hashes recorded in the October 14 audit**. Thus a
successful processing event must not erase an earlier failed-verification
event or be interpreted as proof that the latest downloaded CRL passed. This
is consistent with retaining older usable data; collector fallback behavior
has not been independently audited in source code here.

By October 18, the G1 successful hash is
`bd8f716ef9994931446ce90537ce69e85637aaddcd8a3b34f668e362d8b3d950`, exactly
matching the CRL 12 bytes already preserved in Wayne's incident attachment.
The failed-verification events do **not** include hashes or bytes of the rejected
objects. We cannot bind either failure to an exact raw CRL or independently
diagnose the G3 failure from this telemetry alone.

The October 15 events predate the October 17 intermediate-key disclosure, but
this does not establish a causal link, an undisclosed root-key compromise, or
a new vulnerability. Prior reports already describe the G1 failure. The G3 audit
event is an additional evidence lead whose explanation remains unverified.

An API listing for prefix `202505` returned no objects. That limits what was
retrievable from this bucket under this prefix, not all historical CRL evidence.

## Other longitudinal sources

- [ORC's public CRL directory](https://crl-server.orc.com/CRLs/) exposes yearly
  archives and monthly directories. The downloaded 2005 archive is 441,417 bytes
  compressed. Its subject population is different from the modern WebPKI;
  issuer coverage and signature validity have not been evaluated. Larger yearly
  archives were indexed but not downloaded.
- [Revocation Statuses on the Internet, PAM 2021](https://www.ida.liu.se/~nikca89/papers/pam21.html)
  exposes a research dataset description. It includes parsed CRL snapshots and
  observation-time mappings, but the documentation does not establish that all
  original signed DER objects needed for this study are supplied. The reported
  decompressed storage requirement is about 267 GiB; it was not downloaded.
- The CRLite audit cohort is much more immediately usable than either source
  for studying present-day collector failures, provided we preserve event-level
  semantics and add independent outcome labels before any predictive analysis.

## Reproduce and inspect

```powershell
python restore_expansion.py --download
python summarize_expansion.py
python -m unittest discover -s . -p 'test_*.py' -v
```

Without `--download`, restoration only checks local files. The supplied manifest
pins exact source bytes; public mutable metadata may change and be rejected.
The RAR sample requires a `tar` implementation with RAR reading support; Windows'
bundled libarchive tar worked here. Archives are read as data and are not
extracted to arbitrary filesystem paths.

- `results/incident-index.csv`: all 170 search results.
- `results/expansion-summary.json`: signature outputs, corpus counts and selected
  CRLite events, with their original timestamps and labels.
- `expand.py --artifacts`: bounded collection of the selected incident metadata
  and small attached CRLs/archives. The fixed source manifest is the definitive
  record of the additional public storage and certificate downloads.

Twelve tests pass across the initial and expanded evidence. The new tests
exercise the iTrus payload mismatch and GlobalTrust's signature/name distinction.

## Updated research assessment

There is enough accessible data to pursue a **cross-operator diagnostic study**
of why CRLs fail, how monitoring reports the failure, and which validation
checks distinguish the causes. This is stronger than the initial convenience
sample. A claim that these failures predict later compromise still needs an
explicit sampling design, historical coverage and independently established
outcomes. More audit rows alone cannot supply those labels.

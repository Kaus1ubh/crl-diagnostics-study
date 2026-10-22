---
description: "Fixed checks and interpretation rules for the retrospective CRL diagnostic benchmark"
type: research
status: active
aliases: [CRL diagnostic benchmark protocol]
---
# Diagnostic benchmark protocol v1

Defined before the consolidated benchmark run on 22 October 2026. This is a
retrospective protocol: these historical artifacts have already been inspected.
It is not a blinded test, preregistered study, or estimate of general accuracy.

## Inputs and units

- Include the 19 distinct historical CRLs from the initial and expanded studies.
- Deduplicate by SHA-256 of complete DER bytes. Retain every attachment alias.
- Group repeated snapshots by incident, not as independent successes. There are
  five historical incident groups across four operators: eMudhra May 2025,
  eMudhra G1 October 2026, GlobalSign 2022, iTrusChina 2021, GlobalTrust 2024.
- Use a stated issuer certificate for each artifact, selected from source context
  before computing its diagnostic result. No searching for whichever issuer makes
  the signature pass. Cross-signed certificates with the same public key do not
  create additional independent observations.
- Add three synthetic, local-only CRLs: normal, signed with a different locally
  generated key, and changed after signing. Keep all three out of historical counts.
  Retain their public fixtures and hashes; discard their private keys.
- Exclude the CRLite logs and ORC archive from this benchmark: they lack either
  the failed bytes, curated issuer pairing, or incident labels needed here.

## Five basic checks

| Check | Definition |
|---|---|
| Issuer name | Exact DER equality of CRL issuer and stated certificate subject; a strict byte comparison, not general semantic DN equivalence |
| Key identifiers | CRL AKI keyIdentifier equals certificate SKI; missing identifier yields unknown |
| Algorithm consistency | Inner and outer AlgorithmIdentifier DER match, and declared signature family matches the issuer public-key family; unsupported families yield unknown |
| Raw signature | Verify the original signature over the original TBSCertList using the stated public key and declared digest, independently of the declared signature family |
| OpenSSL CRL check | Run `openssl crl -verify` with only the stated CAfile and default CA path/store disabled; record stdout, stderr and exit status |

This algorithm check is intentionally not a full lint/profile check. In particular,
it does not decide RSA NULL-parameter compliance, curve/digest policy, CRL scope,
critical extensions, revocation contents, time validity or certificate-path trust.
The raw-signature check is a diagnostic operation, not acceptance of the CRL.

All check outcomes are pass/fail/unknown. Tool invocation or parse errors must
not be counted as an ordinary failed signature. Record them as unknown/error.

## Interpretation rules, independent of incident annotations

- Raw signature passes, issuer bytes differ, and normal CRL check fails:
  **verified signature with issuer-name mismatch**.
- Raw signature passes, declared family differs from key family, and normal
  CRL check fails: **verified signature with algorithm-family mismatch**.
- Raw signature fails, while the three metadata checks pass:
  **unresolved signature failure**. Do not label this wrong key or changed bytes.
- All five pass: **no failure in these five checks**, not universally conformant
  or secure.
- Any other pattern: report the individual findings; no forced root-cause label.

After these five checks, run separately labelled supplementary evidence:

- For iTrusChina, test the original signature over the operator-supplied alternate
  TBSCertList. This extra source artifact can establish a different signed payload.
- For the synthetic wrong-key fixture, test the known alternate local public key.
  This deliberately provided key can establish signer mismatch in that control.
- For the synthetic changed-payload fixture, test the retained original payload.

These extensions have additional information unavailable to the basic checks.
Do not present their success as automatic diagnosis from a single CRL.

## Outputs and decision criteria

Produce a row-level CSV, full JSON outputs, an incident-group summary and a
human-readable report. Include artifact/issuer hashes, protocol and runner hashes,
engine version, source aliases, and source-backed annotations separate from
computed diagnoses. Do not report accuracy, precision, recall or significance.

Success is one reproducible diagnostic distinction or a clearly demonstrated
ambiguity. Inspect existing upstream tooling before claiming novelty or proposing
a new tool. A useful test case may be contributed later; no public post, issue or
PR is authorized by this protocol alone.

## Standards and references

- [RFC 5280, section 5](https://www.rfc-editor.org/rfc/rfc5280.html#section-5): CRL structure and signature/issuer fields.
- [RFC 5758, section 3.2](https://www.rfc-editor.org/rfc/rfc5758.html#section-3.2): ECDSA algorithm identifiers.
- Source incidents and existing reproductions: `SOURCES.md`, `FEASIBILITY.md`, and `DATA_EXPANSION.md`.

# Sources and attribution

Collected and analysed on 22 October 2026. This is a reproduction of public
incident evidence. Original reporters and investigators retain discovery credit.

| Group | Primary record | Credit and artifacts |
| --- | --- | --- |
| eMudhra May 2025 | [Bug 1970728](https://bugzilla.mozilla.org/show_bug.cgi?id=1970728) | Reported by Rob Stradling; CA-supplied attachments 9493661–9493666 contain five distinct CRLs |
| eMudhra G1 October 2026 | [Bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) | Wayne's attachment 9664144 contains CRLs 11/12 and issuer certificates; original discovery Wayne, Mozilla analysis Dennis Jackson and colleagues |
| GlobalSign 2022 | [Bug 1793441](https://bugzilla.mozilla.org/show_bug.cgi?id=1793441) | Andrew Ayer's attachment 9296987 and GlobalSign's incident analysis; [issuer certificate](https://secure.globalsign.com/cacert/gsoveccg4r3.crt) |
| iTrusChina 2021 | [Bug 1712664](https://bugzilla.mozilla.org/show_bug.cgi?id=1712664) | Operator-supplied attachment 9223587 includes the wrong CRL, issuer certificate and alternate signed payload |
| GlobalTrust 2024 | [Bug 1888371](https://bugzilla.mozilla.org/show_bug.cgi?id=1888371) | Andrew Ayer's report; individual attachments and attachment 9399932 contain ten distinct CRLs and issuer references |

Additional issuer sources include public certificate-reference JSON from
[the independent eMudhra response site](https://emudhra.we-have-a-problem.com/),
and the GlobalTrust certificate URLs preserved in `expansion/manifest.json`.
PEM issuer certificates were converted to DER before hashing; hashes in
`benchmark/cases.json` identify the exact bytes used.

[provenance.json](provenance.json) connects the frozen cases and their paired
issuer certificates to source URLs, archive members or certificate-reference
records. Duplicate attachment aliases are retained. The original source
manifests preserve source-response hashes; they also list wider collection files
that are not redistributed in this focused benchmark repository.

## Prior work and standards

- [RFC 5280, section 5](https://www.rfc-editor.org/rfc/rfc5280.html#section-5): CRL structure and fields.
- [RFC 5758, section 3.2](https://www.rfc-editor.org/rfc/rfc5758.html#section-3.2): ECDSA identifiers.
- [x509-limbo CRL tests](https://x509-limbo.com/testcases/crl/): existing invalid-signature and wrong-signing-key cases.
- [pkilint CRL validator, inspected commit 820a614](https://github.com/digicert/pkilint/blob/820a6146e255205b8b633de3e36856f011a628e3/pkilint/pkix/crl/crl_validator.py): existing inner/outer algorithm equality check. Source inspected; not a comparative tool execution.
- [Mozilla CRLite data documentation](https://github.com/mozilla/crlite/wiki#where-can-i-get-the-crlite-data-that-is-used-to-make-filters): background audit-event collection. Those events are outside the 19-CRL benchmark.
- [Revocation Statuses on the Internet](https://www.ida.liu.se/~nikca89/papers/pam21.html), Nikita Korzhitskii and Niklas Carlsson, PAM 2021: prior longitudinal CRL/OCSP measurement. Its dataset was not evaluated here.

The collection-phase reports discuss additional dashboard, audit and archive
sources. Those wider observations must not be included in the 19-object
benchmark counts.

## G1 signing-key follow-up, 23 October 2026

[Zihao Wang, Bug 2083449 comment 34](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c34)
identified the OCSP signing certificate for G1 CRL #11. [Wayne's comment 36](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c36)
describes the prior investigation. Supplemental inputs, source URLs and hashes
are in [followups/g1-ocsp/manifest.json](followups/g1-ocsp/manifest.json).

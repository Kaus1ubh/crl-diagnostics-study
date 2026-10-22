"""Five fixed diagnostic checks. Not a general-purpose ASN.1 or trust validator."""
from dataclasses import dataclass
import re
import subprocess

import analyze


@dataclass(frozen=True)
class Node:
    tag: int
    value: bytes
    raw: bytes


def parse(data):
    tag, start, end, raw = analyze.tlv(data, 0, len(data))
    if end != len(data):
        raise ValueError("Trailing DER data")
    return Node(tag, data[start:end], raw)


def children(node):
    result, pos = [], 0
    while pos < len(node.value):
        tag, start, end, raw = analyze.tlv(node.value, pos, len(node.value))
        result.append(Node(tag, node.value[start:end], raw))
        pos = end
    return result


def oid(node):
    if node.tag != 6 or not node.value:
        raise ValueError("Expected nonempty OID")
    numbers, value = [], 0
    for byte in node.value:
        value = (value << 7) | (byte & 127)
        if not byte & 128:
            numbers.append(value)
            value = 0
    if node.value[-1] & 128:
        raise ValueError("Truncated OID")
    first = numbers.pop(0)
    head = (0, first) if first < 40 else (1, first - 40) if first < 80 else (2, first - 80)
    return ".".join(map(str, [*head, *numbers]))


def extension(fields, wrapper_tag, wanted):
    wrappers = [n for n in fields if n.tag == wrapper_tag]
    if not wrappers:
        return None
    sequence, = children(wrappers[0])
    for ext in children(sequence):
        parts = children(ext)
        if oid(parts[0]) == wanted:
            if parts[-1].tag != 4:
                raise ValueError("Expected extension OCTET STRING")
            return parse(parts[-1].value)
    return None


def certificate_parts(der):
    root = parse(der)
    if root.tag != 48:
        raise ValueError("Certificate must be SEQUENCE")
    fields = children(children(root)[0])
    if fields[0].tag == 0xA0:
        fields = fields[1:]
    subject, spki = fields[4], fields[5]
    key_alg = oid(children(children(spki)[0])[0])
    family = {"1.2.840.113549.1.1.1": "rsa", "1.2.840.10045.2.1": "ec"}.get(key_alg)
    ski = extension(fields, 0xA3, "2.5.29.14")
    return {"subject": subject.raw, "family": family,
            "ski": ski.value if ski and ski.tag == 4 else None}


def crl_parts(der):
    root = parse(der)
    parts = children(root)
    if root.tag != 48 or len(parts) != 3:
        raise ValueError("Expected CertificateList")
    tbs, outer, _ = parts
    fields = children(tbs)
    if fields[0].tag == 2:
        fields = fields[1:]
    inner, issuer, this_update = fields[:3]
    aki = extension(fields, 0xA0, "2.5.29.35")
    keyid = next((n.value for n in children(aki) if n.tag == 0x80), None) if aki else None
    _, signature = analyze.signed_parts(der)
    return {"tbs": tbs.raw, "signature": signature, "issuer": issuer.raw,
            "inner": inner.raw, "outer": outer.raw,
            "signature_oid": oid(children(outer)[0]), "aki": keyid,
            "this_update": this_update}


SIGNATURES = {
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.10045.4.3.2": ("ec", "sha256"),
    "1.2.840.10045.4.3.3": ("ec", "sha384"),
    "1.2.840.10045.4.3.4": ("ec", "sha512"),
}
BASIC = ("issuer_name", "key_identifiers", "algorithm_consistency", "raw_signature", "openssl_crl")


def state(value):
    return "unknown" if value is None else "pass" if value else "fail"


def classify(checks):
    """Consumes checks only. Source annotations are not an input."""
    if checks["raw_signature"] == "pass" and checks["openssl_crl"] == "fail":
        if checks["issuer_name"] == "fail":
            return "verified_signature_issuer_name_mismatch"
        if checks["algorithm_consistency"] == "fail":
            return "verified_signature_algorithm_mismatch"
    if checks["raw_signature"] == "fail" and all(checks[k] == "pass" for k in BASIC[:3]):
        return "unresolved_signature_failure"
    if all(checks[k] == "pass" for k in BASIC):
        return "no_failure_in_five_checks"
    return "mixed_or_unknown"


def execute(command, work):
    result = analyze.command(command)
    result["command"] = [p.replace(str(work), "<work>") for p in command]
    for key in ("stdout", "stderr"):
        result[key] = result[key].replace(str(work), "<work>")
        # OpenSSL error-stack addresses are not substantive evidence.
        result[key] = re.sub(r"\b[0-9A-Fa-f]{8,16}:error:", "<address>:error:", result[key])
    return result


def raw_state(result):
    if result["returncode"] == 0 and result["stdout"] == "Verified OK":
        return "pass"
    if "Verification failure" in result["stdout"]:
        return "fail"
    return "unknown"


def normal_state(result):
    output = result["stdout"] + "\n" + result["stderr"]
    if result["returncode"] == 0 and "verify OK" in output:
        return "pass"
    if any(message in output for message in ("verify failure", "Error getting CRL issuer certificate", "wrong public key type")):
        return "fail"
    return "unknown"


def check_pair(openssl, crl, certificate, work):
    crl_data, cert_data = crl_parts(crl), certificate_parts(certificate)
    declared_family, digest = SIGNATURES.get(crl_data["signature_oid"], (None, None))
    identifiers = (crl_data["aki"] == cert_data["ski"]
                   if crl_data["aki"] is not None and cert_data["ski"] is not None else None)
    same_algorithm = crl_data["inner"] == crl_data["outer"]
    family_matches = (declared_family == cert_data["family"]
                      if declared_family is not None and cert_data["family"] is not None else None)
    consistent = False if not same_algorithm or family_matches is False else family_matches
    checks = {"issuer_name": state(crl_data["issuer"] == cert_data["subject"]),
              "key_identifiers": state(identifiers), "algorithm_consistency": state(consistent)}
    (work / "issuer.der").write_bytes(certificate)
    (work / "sample.der").write_bytes(crl)
    (work / "message.bin").write_bytes(crl_data["tbs"])
    (work / "signature.bin").write_bytes(crl_data["signature"])
    public = subprocess.run([openssl, "x509", "-inform", "DER", "-in", str(work / "issuer.der"), "-pubkey", "-noout"],
                            capture_output=True, timeout=15, check=True).stdout
    (work / "public.pem").write_bytes(public)
    pem = subprocess.run([openssl, "x509", "-inform", "DER", "-in", str(work / "issuer.der"), "-outform", "PEM"],
                         capture_output=True, timeout=15, check=True).stdout
    (work / "issuer.pem").write_bytes(pem)
    raw = execute([openssl, "dgst", "-" + digest, "-verify", str(work / "public.pem"), "-signature",
                   str(work / "signature.bin"), str(work / "message.bin")], work) if digest else None
    normal = execute([openssl, "crl", "-inform", "DER", "-in", str(work / "sample.der"), "-verify", "-noout",
                      "-CAfile", str(work / "issuer.pem"), "-no-CApath", "-no-CAstore"], work)
    checks["raw_signature"] = raw_state(raw) if raw else "unknown"
    checks["openssl_crl"] = normal_state(normal)
    return {"checks": checks, "diagnosis": classify(checks),
            "metadata": {"issuer_der_sha256": analyze.sha(crl_data["issuer"]),
                         "subject_der_sha256": analyze.sha(cert_data["subject"]),
                         "aki": crl_data["aki"].hex().upper() if crl_data["aki"] is not None else None,
                         "ski": cert_data["ski"].hex().upper() if cert_data["ski"] is not None else None,
                         "inner_algorithm_der": crl_data["inner"].hex(), "outer_algorithm_der": crl_data["outer"].hex(),
                         "signature_oid": crl_data["signature_oid"], "inner_outer_equal": same_algorithm,
                         "signature_key_family_matches": family_matches},
            "raw_output": raw, "normal_output": normal}

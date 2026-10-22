"""Shared hashing, OpenSSL invocation and DER helpers for the frozen benchmark."""
import hashlib
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def command(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=15)
    return {"returncode": result.returncode,
            "stdout": result.stdout.decode("utf-8", errors="replace").strip(),
            "stderr": result.stderr.decode("utf-8", errors="replace").strip()}


def tlv(data, offset, limit):
    start = offset
    if offset + 2 > limit:
        raise ValueError("Truncated DER")
    tag, length = data[offset:offset + 2]
    offset += 2
    if length & 128:
        count = length & 127
        if not count or count > 4 or offset + count > limit:
            raise ValueError("Invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > limit:
        raise ValueError("Truncated DER value")
    return tag, offset, end, data[start:end]


def signed_parts(der):
    tag, pos, end, _ = tlv(der, 0, len(der))
    if tag != 48 or end != len(der):
        raise ValueError("Expected complete CRL sequence")
    tag, _, pos, tbs = tlv(der, pos, end)
    if tag != 48:
        raise ValueError("Expected TBSCertList")
    tag, _, pos, _ = tlv(der, pos, end)
    if tag != 48:
        raise ValueError("Expected signature AlgorithmIdentifier")
    tag, body, final, _ = tlv(der, pos, end)
    if tag != 3 or final != end or body >= final or der[body] != 0:
        raise ValueError("Invalid signature BIT STRING")
    return tbs, der[body + 1:final]

"""Create local synthetic controls once; only public artifacts survive the temporary directory."""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import analyze
import benchmark_checks as checks

HERE = Path(__file__).resolve().parent
OUT = HERE / "benchmark" / "synthetic"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new-snapshot", action="store_true", help="Explicitly replace locally generated public controls")
    args = parser.parse_args()
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("OpenSSL required")
    OUT.mkdir(parents=True, exist_ok=True)
    lock = OUT / "manifest.json"
    if lock.exists() and not args.new_snapshot:
        for item in json.loads(lock.read_text())["files"]:
            if analyze.sha((OUT / item["file"]).read_bytes()) != item["sha256"]:
                raise ValueError("Existing control changed")
        print("Verified existing synthetic controls")
        return
    outputs = {}
    with tempfile.TemporaryDirectory(dir=OUT, prefix="work-") as folder:
        work = Path(folder)

        def run(args):
            subprocess.run([openssl, *args], cwd=work, capture_output=True, timeout=30, check=True)

        for name in ("A", "B"):
            run(["req", "-x509", "-newkey", "rsa:2048", "-noenc", "-sha256", "-days", "30",
                 "-keyout", name + ".key", "-out", name + ".pem",
                 "-subj", "/O=Local Test Only/CN=CRL Benchmark Synthetic " + name,
                 "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-addext", "subjectKeyIdentifier=hash"])
            run(["x509", "-in", name + ".pem", "-outform", "DER", "-out", name + ".der"])
            outputs[name + ".der"] = (work / (name + ".der")).read_bytes()
        for name, text in [("index.txt", ""), ("serial", "01\n"), ("crlnumber", "01\n")]:
            (work / name).write_text(text)
        (work / "ca.cnf").write_text("""[ca]
default_ca=local
[local]
database=index.txt
serial=serial
crlnumber=crlnumber
private_key=A.key
certificate=A.pem
default_md=sha256
default_crl_days=7
crl_extensions=crl_ext
[crl_ext]
authorityKeyIdentifier=keyid:always
""")
        run(["ca", "-config", "ca.cnf", "-gencrl", "-batch", "-out", "base.pem"])
        run(["crl", "-in", "base.pem", "-outform", "DER", "-out", "normal.crl"])
        normal = (work / "normal.crl").read_bytes()
        fields = checks.crl_parts(normal)
        (work / "tbs.bin").write_bytes(fields["tbs"])
        run(["dgst", "-sha256", "-sign", "B.key", "-out", "wrong-signature.bin", "tbs.bin"])

        def encode(tag, value):
            length = len(value)
            if length < 128:
                header = bytes([tag, length])
            else:
                encoded_length = length.to_bytes((length.bit_length() + 7) // 8, "big")
                header = bytes([tag, 128 | len(encoded_length)]) + encoded_length
            return header + value

        wrong = encode(48, fields["tbs"] + fields["outer"] + encode(3, b"\0" + (work / "wrong-signature.bin").read_bytes()))
        time = fields["this_update"].raw
        # Change only the seconds' final decimal digit; DER structure remains intact.
        changed_time = time[:-2] + (b"1" if time[-2:-1] == b"0" else b"0") + time[-1:]
        if normal.count(time) != 1:
            raise ValueError("Expected a unique thisUpdate field")
        outputs["normal.crl"] = normal
        outputs["wrong-key.crl"] = wrong
        outputs["changed-payload.crl"] = normal.replace(time, changed_time, 1)
        outputs["original-tbs.der"] = fields["tbs"]
        if len({outputs[name] for name in ("normal.crl", "wrong-key.crl", "changed-payload.crl")}) != 3:
            raise ValueError("Controls must be three distinct artifacts")
        # Check the actual signed bytes before publishing any fixtures.
        for fixture, signer, should_pass in [("normal.crl", "A", True), ("wrong-key.crl", "A", False),
                                            ("wrong-key.crl", "B", True), ("changed-payload.crl", "A", False)]:
            parts = checks.crl_parts(outputs[fixture])
            (work / "message.bin").write_bytes(parts["tbs"])
            (work / "signature.bin").write_bytes(parts["signature"])
            run(["x509", "-in", signer + ".pem", "-pubkey", "-noout", "-out", "public.pem"])
            result = subprocess.run([openssl, "dgst", "-sha256", "-verify", "public.pem", "-signature", "signature.bin", "message.bin"],
                                    cwd=work, capture_output=True, timeout=15)
            if (result.returncode == 0 and result.stdout.strip() == b"Verified OK") != should_pass:
                raise ValueError("Synthetic signature control failed: " + fixture + " / " + signer)
    for name, data in outputs.items():
        (OUT / name).write_bytes(data)
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(),
                "description": "Synthetic controls only. Keys A/B were local ephemeral keys, not public CA keys. Private keys discarded.",
                "files": [{"file": name, "sha256": analyze.sha(data)} for name, data in outputs.items()]}
    lock.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Created", len(outputs), "public synthetic control files; no private keys retained")


if __name__ == "__main__":
    main()

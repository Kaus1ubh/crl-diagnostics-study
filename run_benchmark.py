"""Run fixed diagnostic checks on the frozen historical and synthetic case set."""
import collections
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import analyze
import benchmark_checks as check

HERE = Path(__file__).resolve().parent
DATA = HERE / "benchmark"


def main():
    openssl = shutil.which("openssl")
    if not openssl:
        raise SystemExit("OpenSSL required")
    cases = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))
    if analyze.sha((HERE / "BENCHMARK_PROTOCOL.md").read_bytes()) != cases["protocol_sha256"]:
        raise ValueError("Frozen protocol changed")
    for item in cases["files"]:
        path = DATA / item["file"]
        if not path.resolve().is_relative_to(DATA.resolve()) or analyze.sha(path.read_bytes()) != item["sha256"]:
            raise ValueError("Input hash or path mismatch")
    output = HERE / "results"
    output.mkdir(exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(dir=output, prefix="work-") as folder:
        work = Path(folder)
        for case in cases["cases"]:
            crl = (DATA / case["crl_file"]).read_bytes()
            cert = (DATA / case["issuer_file"]).read_bytes()
            try:
                measured = check.check_pair(openssl, crl, cert, work)
                enriched = None
                supplement = case["supplement"]
                if supplement:
                    parts = check.crl_parts(crl)
                    (work / "signature.bin").write_bytes(parts["signature"])
                    if supplement["type"] == "alternate_payload":
                        (work / "message.bin").write_bytes((DATA / supplement["file"]).read_bytes())
                    elif supplement["type"] == "alternate_issuer":
                        public = subprocess.run([openssl, "x509", "-inform", "DER", "-pubkey", "-noout"],
                                                input=(DATA / supplement["file"]).read_bytes(), capture_output=True, timeout=15, check=True).stdout
                        (work / "public.pem").write_bytes(public)
                    digest = check.SIGNATURES[parts["signature_oid"]][1]
                    result = check.execute([openssl, "dgst", "-" + digest, "-verify", str(work / "public.pem"),
                                            "-signature", str(work / "signature.bin"), str(work / "message.bin")], work)
                    enriched = {"type": supplement["type"], "status": check.raw_state(result), "output": result,
                                "extra_information_required": supplement["source"]}
            except (ValueError, IndexError, KeyError, OSError, subprocess.SubprocessError) as exc:
                measured = {"checks": {k: "unknown" for k in check.BASIC}, "diagnosis": "mixed_or_unknown", "error": str(exc)}
                enriched = None
            # Annotations are carried through for review; classify() receives only measured checks.
            results.append({**case, **measured, "supplementary_evidence": enriched})
    groups = []
    for name in sorted({x["group"] for x in results}):
        rows = [x for x in results if x["group"] == name]
        groups.append({"group": name, "kind": rows[0]["kind"], "distinct_crls": len(rows),
                       "diagnoses": dict(collections.Counter(x["diagnosis"] for x in rows))})
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "engine": analyze.command([openssl, "version"])["stdout"],
              "protocol_sha256": cases["protocol_sha256"], "case_manifest_sha256": analyze.sha((DATA / "cases.json").read_bytes()),
              "runner_sha256": analyze.sha(Path(__file__).read_bytes()), "checks_sha256": analyze.sha((HERE / "benchmark_checks.py").read_bytes()),
              "groups": groups, "results": results}
    (output / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    with (output / "benchmark.csv").open("w", encoding="utf-8", newline="") as handle:
        fields = ["id", "kind", "group", *check.BASIC, "diagnosis", "source_annotation", "supplement_type", "supplement_status"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in results:
            extra = row["supplementary_evidence"] or {}
            writer.writerow({**{key: row[key] for key in fields[:3]}, **row["checks"], "diagnosis": row["diagnosis"],
                             "source_annotation": row["source_annotation"], "supplement_type": extra.get("type", ""),
                             "supplement_status": extra.get("status", "")})
    for group in groups:
        print(group)
    print("Unknown checks:", sum(value == "unknown" for row in results for value in row["checks"].values()))
    return 2 if any(row.get("error") for row in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())

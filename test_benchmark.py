import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import analyze
import benchmark_checks as check

HERE = Path(__file__).resolve().parent
DATA = HERE / "benchmark"


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl = shutil.which("openssl")
        if not cls.openssl:
            raise unittest.SkipTest("OpenSSL required")
        cls.cases = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))

    def pair(self, name):
        with tempfile.TemporaryDirectory(dir=HERE) as folder:
            return check.check_pair(self.openssl, (DATA / "synthetic" / (name + ".crl")).read_bytes(),
                                    (DATA / "synthetic" / "A.der").read_bytes(), Path(folder))

    def test_constructed_failures_have_identical_basic_observations(self):
        wrong, changed = self.pair("wrong-key"), self.pair("changed-payload")
        self.assertEqual(wrong["checks"], changed["checks"])
        self.assertEqual(wrong["diagnosis"], "unresolved_signature_failure")
        self.assertEqual(changed["diagnosis"], "unresolved_signature_failure")

    def test_synthetic_normal_passes_all_five(self):
        self.assertTrue(all(x == "pass" for x in self.pair("normal")["checks"].values()))

    def test_known_alternate_key_verifies_only_the_wrong_key_control(self):
        certificate = (DATA / "synthetic" / "B.der").read_bytes()
        public = subprocess.run([self.openssl, "x509", "-inform", "DER", "-pubkey", "-noout"],
                                input=certificate, capture_output=True, timeout=10, check=True).stdout
        with tempfile.TemporaryDirectory(dir=HERE) as folder:
            work = Path(folder)
            (work / "public.pem").write_bytes(public)
            for name, expected in [("wrong-key", "pass"), ("changed-payload", "fail")]:
                fields = check.crl_parts((DATA / "synthetic" / (name + ".crl")).read_bytes())
                (work / "message").write_bytes(fields["tbs"])
                (work / "signature").write_bytes(fields["signature"])
                result = check.execute([self.openssl, "dgst", "-sha256", "-verify", str(work / "public.pem"),
                                        "-signature", str(work / "signature"), str(work / "message")], work)
                self.assertEqual(check.raw_state(result), expected)

    def test_unknown_tool_errors_are_not_signature_failures(self):
        result = {"returncode": 1, "stdout": "", "stderr": "Unknown option: -unsupported"}
        self.assertEqual(check.raw_state(result), "unknown")
        self.assertEqual(check.normal_state(result), "unknown")

    def test_global_sign_has_matching_algorithms_but_wrong_key_family(self):
        case, = [x for x in self.cases["cases"] if x["group"] == "globalsign-2022"]
        with tempfile.TemporaryDirectory(dir=HERE) as folder:
            row = check.check_pair(self.openssl, (DATA / case["crl_file"]).read_bytes(),
                                   (DATA / case["issuer_file"]).read_bytes(), Path(folder))
        self.assertTrue(row["metadata"]["inner_outer_equal"])
        self.assertFalse(row["metadata"]["signature_key_family_matches"])
        self.assertEqual(row["checks"]["raw_signature"], "pass")
        self.assertEqual(row["diagnosis"], "verified_signature_algorithm_mismatch")

    def test_frozen_manifest_and_protocol(self):
        self.assertEqual(analyze.sha((HERE / "BENCHMARK_PROTOCOL.md").read_bytes()), self.cases["protocol_sha256"])
        for item in self.cases["files"]:
            self.assertEqual(analyze.sha((DATA / item["file"]).read_bytes()), item["sha256"])
        self.assertEqual(sum(x["kind"] == "historical" for x in self.cases["cases"]), 19)
        self.assertEqual(sum(x["kind"] == "synthetic" for x in self.cases["cases"]), 3)
        self.assertEqual(len({x["crl_sha256"] for x in self.cases["cases"]}), 22)

    def test_duplicate_historical_attachment_is_retained_as_alias(self):
        case, = [x for x in self.cases["cases"] if "evidence/attachment-9493661.crl" in x["aliases"]]
        self.assertIn("evidence/attachment-9493663.crl", case["aliases"])

    def test_no_private_key_artifacts(self):
        self.assertFalse(list(DATA.rglob("*.key")))
        self.assertFalse(list(DATA.rglob("work-*")))


if __name__ == "__main__":
    unittest.main()

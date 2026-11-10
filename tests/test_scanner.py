"""Regression tests for the Network Footprint scanner.

Run from the repo root:
    python3 -m unittest discover tests

Standard library only, like the scanner itself.
"""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "skills" / "network-footprint" / "scripts"
SAMPLE = ROOT / "samples" / "sample-app"
sys.path.insert(0, str(SCRIPTS))

import footprint_scan  # noqa: E402
from footprint_network_scanner import redact  # noqa: E402


def run_scan(target):
    with redirect_stdout(io.StringIO()):
        rc = footprint_scan.main(["footprint_scan.py", str(target)])
    assert rc == 0, "scan failed"
    findings = Path(target) / "findings"
    with open(findings / "footprint.json", encoding="utf-8") as f:
        index = json.load(f)
    return index, findings


def all_findings_text(findings):
    chunks = []
    for p in findings.rglob("*.json"):
        chunks.append(p.read_text(encoding="utf-8"))
    return "\n".join(chunks)


class SampleAppTest(unittest.TestCase):
    """The bundled sample app is the answer key (samples/EXPECTATIONS.md)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.target = Path(cls.tmp) / "sample-app"
        shutil.copytree(SAMPLE, cls.target)
        cls.index, cls.findings = run_scan(cls.target)
        cls.by_host = {e["host"]: e for e in cls.index["endpoints"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_expected_endpoints(self):
        expected = {
            "52.20.16.7", "54.230.0.10",
            "acme-artifacts.s3.us-east-2.amazonaws.com", "acme.us.auth0.com",
            "api.acme-service.com", "api.datadoghq.com", "api.docparser.io",
            "api.exchangerate.host", "cdn.jsdelivr.net", "collector.mixpanel.com",
            "export.old-partner.net", "hooks.billing-vendor.com",
            "o0.ingest.sentry.io", "registry.npmjs.org",
            "s3.us-east-2.amazonaws.com", "status.acme-service.com",
            "storage.googleapis.com", "stream.acme-realtime.com",
        }
        self.assertEqual(set(self.by_host), expected)

    def test_private_and_docs_not_detected(self):
        for host in ("192.168.10.5", "127.0.0.1", "localhost",
                     "docs.acme-service.com", "wiki.internal.example"):
            self.assertNotIn(host, self.by_host)

    def test_code_identifiers_excluded(self):
        excluded = self.index["excluded_identifiers"]
        for prefix in ("com.acme.sample.legacy", "org.springframework.boot",
                       "com.fasterxml.jackson.databind", "java.net.http"):
            self.assertTrue(any(e.startswith(prefix) for e in excluded), prefix)
        self.assertFalse(any(h.startswith(("org.", "com.", "java.")) for h in self.by_host))

    def test_config_only_endpoints(self):
        for host in ("s3.us-east-2.amazonaws.com", "acme.us.auth0.com",
                     "hooks.billing-vendor.com", "export.old-partner.net",
                     "cdn.jsdelivr.net", "o0.ingest.sentry.io"):
            self.assertEqual(self.by_host[host]["usage"], "config", host)
            self.assertEqual(self.by_host[host]["direction"], "NONE", host)

    def test_config_key_traced_to_code(self):
        ep = self.by_host["api.acme-service.com"]
        self.assertEqual(ep["usage"], "code")
        self.assertIn("service.uploadUrl", ep["config_keys"])

    def test_sentry_config_key_found_despite_masking(self):
        self.assertEqual(self.by_host["o0.ingest.sentry.io"]["config_keys"],
                         ["observability.sentryDsn"])

    def test_template_paths_kept_whole(self):
        self.assertIn("/v1/users/${id}", self.by_host["api.acme-service.com"]["paths"])
        self.assertIn("/${pkg}/latest", self.by_host["registry.npmjs.org"]["paths"])

    def test_no_credentials_in_findings(self):
        text = all_findings_text(self.findings)
        self.assertNotIn("s3cr3t", text)
        self.assertNotIn("examplePublicKey", text)
        self.assertIn("app_user:***@52.20.16.7", text)


class EdgeCaseTest(unittest.TestCase):
    """False positives and secret handling found in the 1.0.0 review."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        t = Path(cls.tmp)
        (t / "src").mkdir()
        (t / "config").mkdir()
        (t / "deploy.sh").write_text("echo hi\n")
        (t / "src" / "a.py").write_text(
            'import subprocess\n'
            'subprocess.run(["bash", "deploy.sh"])\n'
            'x = data.in\n'
            'log.info("starting")\n'
            'url = "https://api.real.com/v1"\n'
            's = f"https://{HOST}/path"\n'
            't = "https://$BASE/x"\n'
            'host = "api.bare-domain.com"\n'
            'headers = {"Authorization": "Bearer abcdef1234567890XYZ"}\n'
            'token = get_token()\n'
            'r = requests.get("https://api.q.com/data?api_key=SUPERSECRET123&page=2")\n'
            'wiki = "https://en.wikipedia.org/wiki/Foo_(bar)"\n',
            encoding="utf-8",
        )
        (t / "config" / "app.env").write_text(
            "DB_PASSWORD=hunter2\nAPI_HOST=api.envhost.io\n", encoding="utf-8")
        (t / "config" / "s.yaml").write_text(
            "upstream:\n  host: data.partner.co\n  password: plainpw\n", encoding="utf-8")
        cls.index, cls.findings = run_scan(t)
        cls.by_host = {e["host"]: e for e in cls.index["endpoints"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_real_endpoints_found(self):
        for host in ("api.real.com", "api.bare-domain.com", "api.q.com",
                     "en.wikipedia.org", "api.envhost.io", "data.partner.co"):
            self.assertIn(host, self.by_host)

    def test_false_positives_dropped(self):
        for host in ("deploy.sh", "data.in", "log.info"):
            self.assertNotIn(host, self.by_host)
        self.assertFalse(any("{" in h or "$" in h for h in self.by_host))
        self.assertEqual(self.index["summary"]["templated_urls_skipped"], 2)

    def test_balanced_parens_in_path(self):
        self.assertEqual(self.by_host["en.wikipedia.org"]["paths"], ["/wiki/Foo_(bar)"])

    def test_secrets_masked(self):
        text = all_findings_text(self.findings)
        for secret in ("hunter2", "plainpw", "SUPERSECRET123", "abcdef1234567890XYZ"):
            self.assertNotIn(secret, text)
        self.assertIn("api_key=***&page=2", text)
        self.assertIn("get_token()", text)  # code expressions are left alone


class RedactTest(unittest.TestCase):
    def test_userinfo(self):
        self.assertEqual(redact("redis://u:p@h:6379/0"), "redis://u:***@h:6379/0")
        self.assertEqual(redact("https://key@sentry.io/1"), "https://***@sentry.io/1")
        self.assertEqual(redact("git@github.com:org/repo.git"), "git@github.com:org/repo.git")

    def test_quoted_and_bare(self):
        self.assertEqual(redact('password = "x1"'), 'password = "***"')
        self.assertEqual(redact("password=x1"), "password=x1")
        self.assertEqual(redact("password=x1", bare_values=True), "password=***")

    def test_plain_lines_untouched(self):
        line = 'resp = requests.get("https://api.example.io/v1/items?page=2")'
        self.assertEqual(redact(line), line)


if __name__ == "__main__":
    unittest.main()

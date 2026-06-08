"""Smoke tests for AUTHMATRIX. Standard library only, no network."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from authmatrix import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    analyze,
    load_matrix,
    Observation,
)
from authmatrix.cli import main  # noqa: E402


BASE = {
    "roles": [
        {"name": "anon", "privilege": 0},
        {"name": "admin", "privilege": 3},
    ],
    "endpoints": [
        {"name": "pii", "method": "GET", "path": "/u/{id}", "sensitive": True},
        {"name": "home", "method": "GET", "path": "/", "sensitive": False},
    ],
    "policy": [
        {"role": "anon", "endpoint": "pii", "expected": "deny"},
        {"role": "anon", "endpoint": "home", "expected": "allow"},
        {"role": "admin", "endpoint": "pii", "expected": "allow"},
    ],
    "observations": [
        {"role": "anon", "endpoint": "pii", "status": 200},
        {"role": "anon", "endpoint": "home", "status": 200},
        {"role": "admin", "endpoint": "pii", "status": 200},
    ],
}


class TestMeta(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "authmatrix")
        self.assertTrue(TOOL_VERSION)


class TestEngine(unittest.TestCase):
    def test_idor_overpermission_is_critical(self):
        findings = analyze(load_matrix(BASE))
        idor = [f for f in findings if f.kind == "IDOR_OVERPERMISSION"]
        self.assertEqual(len(idor), 1)
        self.assertEqual(idor[0].role, "anon")
        self.assertEqual(idor[0].endpoint, "pii")
        self.assertEqual(idor[0].severity, "critical")

    def test_clean_matrix_has_no_findings(self):
        clean = json.loads(json.dumps(BASE))
        clean["observations"][0]["status"] = 403
        findings = analyze(load_matrix(clean))
        self.assertEqual(findings, [])

    def test_broken_allow_detected(self):
        d = json.loads(json.dumps(BASE))
        d["observations"][0]["status"] = 403
        d["observations"][2]["status"] = 403
        findings = analyze(load_matrix(d))
        kinds = {f.kind for f in findings}
        self.assertIn("BROKEN_ALLOW", kinds)

    def test_uncovered_cell(self):
        d = json.loads(json.dumps(BASE))
        d["observations"] = [d["observations"][1]]
        findings = analyze(load_matrix(d))
        self.assertTrue(any(f.kind == "UNCOVERED" for f in findings))

    def test_missing_denial_for_undeclared(self):
        d = json.loads(json.dumps(BASE))
        d["observations"][0]["status"] = 403
        d["endpoints"].append({"name": "secret", "path": "/secret"})
        d["observations"].append(
            {"role": "anon", "endpoint": "secret", "status": 200}
        )
        findings = analyze(load_matrix(d))
        self.assertTrue(any(f.kind == "MISSING_DENIAL" for f in findings))

    def test_server_error_inconclusive(self):
        d = json.loads(json.dumps(BASE))
        d["observations"][0]["status"] = 503
        findings = analyze(load_matrix(d))
        self.assertTrue(any(f.kind == "SERVER_ERROR" for f in findings))

    def test_effective_decision_mapping(self):
        self.assertEqual(Observation("r", "e", 204).effective_decision(), "allow")
        self.assertEqual(Observation("r", "e", 302).effective_decision(), "allow")
        self.assertEqual(Observation("r", "e", 401).effective_decision(), "deny")
        self.assertEqual(Observation("r", "e", 404).effective_decision(), "deny")
        self.assertEqual(Observation("r", "e", 500).effective_decision(), "error")

    def test_bad_policy_rejected(self):
        d = json.loads(json.dumps(BASE))
        d["policy"][0]["expected"] = "maybe"
        with self.assertRaises(ValueError):
            load_matrix(d)


class TestCli(unittest.TestCase):
    def _capture(self, argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        old = (sys.stdout, sys.stderr, sys.stdin)
        sys.stdout, sys.stderr = out, err
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            code = main(argv)
        finally:
            sys.stdout, sys.stderr, sys.stdin = old
        return code, out.getvalue(), err.getvalue()

    def test_scan_json_via_stdin_exits_nonzero(self):
        code, out, _ = self._capture(
            ["scan", "-", "--format", "json"], stdin=json.dumps(BASE)
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "authmatrix")
        self.assertGreaterEqual(payload["summary"]["total"], 1)

    def test_scan_table_clean_exits_zero(self):
        clean = json.loads(json.dumps(BASE))
        clean["observations"][0]["status"] = 403
        code, out, _ = self._capture(["scan", "-"], stdin=json.dumps(clean))
        self.assertEqual(code, 0)
        self.assertIn("No authorization gaps", out)

    def test_fail_on_high_ignores_low(self):
        d = json.loads(json.dumps(BASE))
        d["observations"] = [d["observations"][1]]
        code, _, _ = self._capture(
            ["scan", "-", "--fail-on", "high"], stdin=json.dumps(d)
        )
        self.assertEqual(code, 0)

    def test_bad_input_exits_two(self):
        code, _, err = self._capture(["scan", "-"], stdin="{not json")
        self.assertEqual(code, 2)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()

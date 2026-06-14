"""Hardening tests for AUTHMATRIX — edge cases, bad input, error paths."""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from authmatrix.core import load_matrix, analyze, AuthMatrix, Endpoint, PolicyCell  # noqa: E402
from authmatrix.cli import main  # noqa: E402


def _capture(argv, stdin_text=None):
    """Run main() capturing stdout/stderr; return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    old_out, old_err, old_in = sys.stdout, sys.stderr, sys.stdin
    sys.stdout, sys.stderr = out, err
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        code = main(argv)
    finally:
        sys.stdout, sys.stderr, sys.stdin = old_out, old_err, old_in
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# load_matrix — bad input validation
# ---------------------------------------------------------------------------

class TestLoadMatrixBadInput(unittest.TestCase):

    def _base(self):
        return {
            "roles": [{"name": "r", "privilege": 0}],
            "endpoints": [{"name": "e"}],
            "policy": [],
            "observations": [],
        }

    def test_missing_status_field_raises_value_error(self):
        d = self._base()
        d["observations"] = [{"role": "r", "endpoint": "e"}]  # no 'status' key
        with self.assertRaises(ValueError) as ctx:
            load_matrix(d)
        self.assertIn("status", str(ctx.exception))

    def test_null_status_raises_value_error(self):
        d = self._base()
        d["observations"] = [{"role": "r", "endpoint": "e", "status": None}]
        with self.assertRaises(ValueError) as ctx:
            load_matrix(d)
        self.assertIn("status", str(ctx.exception))

    def test_string_status_raises_value_error(self):
        d = self._base()
        d["observations"] = [{"role": "r", "endpoint": "e", "status": "ok"}]
        with self.assertRaises(ValueError) as ctx:
            load_matrix(d)
        self.assertIn("status", str(ctx.exception))

    def test_non_integer_privilege_raises_value_error(self):
        d = self._base()
        d["roles"] = [{"name": "r", "privilege": "admin"}]
        with self.assertRaises(ValueError) as ctx:
            load_matrix(d)
        self.assertIn("privilege", str(ctx.exception))

    def test_null_roles_list_treated_as_empty(self):
        """A JSON null for a list key should not crash — treat as empty."""
        d = self._base()
        d["roles"] = None
        d["policy"] = []
        d["observations"] = []
        matrix = load_matrix(d)
        self.assertEqual(matrix.roles, {})

    def test_non_list_roles_raises_value_error(self):
        d = self._base()
        d["roles"] = {"name": "r"}  # dict instead of list
        with self.assertRaises(ValueError) as ctx:
            load_matrix(d)
        self.assertIn("list", str(ctx.exception))

    def test_non_dict_item_in_roles_raises_value_error(self):
        d = self._base()
        d["roles"] = ["not_a_dict"]
        with self.assertRaises(ValueError) as ctx:
            load_matrix(d)
        self.assertIn("object", str(ctx.exception))

    def test_top_level_not_dict_raises_value_error(self):
        with self.assertRaises(ValueError):
            load_matrix([])

    def test_empty_matrix_produces_no_findings(self):
        """A completely empty matrix (no roles/endpoints/policy/observations) is valid."""
        matrix = load_matrix({})
        findings = analyze(matrix)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# analyze() — defensive guard when AuthMatrix is constructed directly
# ---------------------------------------------------------------------------

class TestAnalyzeDefensiveGuard(unittest.TestCase):

    def test_analyze_raises_on_unknown_policy_role(self):
        """If AuthMatrix is built with a policy cell pointing to a missing role,
        analyze() should raise ValueError, not KeyError."""
        matrix = AuthMatrix(
            roles={},
            endpoints={"e": Endpoint(name="e")},
            policy=[PolicyCell(role="ghost", endpoint="e", expected="deny")],
            observations=[],
        )
        with self.assertRaises(ValueError) as ctx:
            analyze(matrix)
        self.assertIn("ghost", str(ctx.exception))


# ---------------------------------------------------------------------------
# CLI — error paths exit with code 2 and print to stderr
# ---------------------------------------------------------------------------

class TestCliErrorPaths(unittest.TestCase):

    def test_missing_file_exits_two(self):
        code, _, err = _capture(["scan", "/no/such/file.json"])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_malformed_json_exits_two(self):
        code, _, err = _capture(["scan", "-"], stdin_text="{bad json}")
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_missing_status_exits_two_via_cli(self):
        """Missing 'status' in an observation must be caught and exit 2."""
        d = {
            "roles": [{"name": "r"}],
            "endpoints": [{"name": "e"}],
            "policy": [],
            "observations": [{"role": "r", "endpoint": "e"}],
        }
        code, _, err = _capture(["scan", "-"], stdin_text=json.dumps(d))
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_directory_path_exits_two(self):
        """Passing a directory as the matrix path must exit 2, not crash."""
        # Use a known directory that exists
        dirpath = tempfile.gettempdir()
        code, _, err = _capture(["scan", dirpath])
        self.assertEqual(code, 2)
        self.assertIn("error", err.lower())

    def test_valid_matrix_file_exits_zero_when_clean(self):
        """Sanity: scanning a valid clean matrix via a real file returns 0."""
        clean = {
            "roles": [{"name": "anon", "privilege": 0}],
            "endpoints": [{"name": "home", "path": "/"}],
            "policy": [{"role": "anon", "endpoint": "home", "expected": "allow"}],
            "observations": [{"role": "anon", "endpoint": "home", "status": 200}],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".json", encoding="utf-8"
        ) as tmp:
            json.dump(clean, tmp)
            tmp_path = tmp.name
        try:
            code, out, _ = _capture(["scan", tmp_path])
            self.assertEqual(code, 0)
            self.assertIn("No authorization gaps", out)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()

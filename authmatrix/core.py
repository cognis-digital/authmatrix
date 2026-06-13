"""Core engine for AUTHMATRIX.

Model
-----
An access-control matrix is a grid of (role x endpoint) cells. Each cell has:
  - an EXPECTED decision from policy: "allow" or "deny"
  - zero or more OBSERVED outcomes from authorized testing (status codes the
    role actually got when hitting the endpoint)

The engine maps an observed HTTP status to an effective decision:
  2xx / 3xx  -> "allow"  (request succeeded / resource served)
  401 / 403  -> "deny"   (auth challenge / forbidden)
  404        -> "deny"   (treated as not-reachable; common IDOR-hardening)
  other 4xx  -> "deny"
  5xx        -> "error"  (inconclusive)

It then compares effective vs expected and classifies each cell.

Finding classes
---------------
  IDOR_OVERPERMISSION : policy says deny, role was allowed (CRITICAL/HIGH)
  MISSING_DENIAL      : observed allow on a cell with no policy rule
  BROKEN_ALLOW        : policy says allow, role was denied (availability bug)
  UNCOVERED           : a policy cell with no observations at all
  SERVER_ERROR        : observation returned 5xx, inconclusive

Pure standard library. No network. The tool consumes a JSON test artifact;
producing that artifact (the actual requests) is the operator's job and must
be performed only against systems you are authorized to test.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Tuple


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------
class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    _ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls._ORDER.get(sev, -1)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Role:
    name: str
    # higher privilege number == more trusted; used to grade severity
    privilege: int = 0


@dataclass(frozen=True)
class Endpoint:
    name: str
    method: str = "GET"
    path: str = ""
    sensitive: bool = False  # touches PII / money / admin -> raises severity


@dataclass(frozen=True)
class PolicyCell:
    role: str
    endpoint: str
    expected: str  # "allow" | "deny"


@dataclass
class Observation:
    role: str
    endpoint: str
    status: int
    note: str = ""

    def effective_decision(self) -> str:
        s = self.status
        if 200 <= s < 400:
            return "allow"
        if 500 <= s < 600:
            return "error"
        # 401/403/404/other 4xx all mean the role did not get the resource
        return "deny"


@dataclass
class Finding:
    kind: str
    severity: str
    role: str
    endpoint: str
    expected: str
    effective: str
    statuses: List[int] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthMatrix:
    roles: Dict[str, Role]
    endpoints: Dict[str, Endpoint]
    policy: List[PolicyCell]
    observations: List[Observation]


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_matrix(data: Dict[str, Any]) -> AuthMatrix:
    """Build an AuthMatrix from a parsed JSON document.

    Expected schema (see demos/01-basic for an example)::

        {
          "roles":     [{"name": "anon", "privilege": 0}, ...],
          "endpoints": [{"name": "get_user", "method": "GET",
                         "path": "/api/users/{id}", "sensitive": true}, ...],
          "policy":    [{"role": "anon", "endpoint": "get_user",
                         "expected": "deny"}, ...],
          "observations": [{"role": "anon", "endpoint": "get_user",
                            "status": 200, "note": "leaked!"}, ...]
        }
    """
    if not isinstance(data, dict):
        raise ValueError("matrix document must be a JSON object")

    roles: Dict[str, Role] = {}
    for r in data.get("roles", []):
        if "name" not in r:
            raise ValueError("each role requires a 'name'")
        roles[r["name"]] = Role(name=r["name"], privilege=int(r.get("privilege", 0)))

    endpoints: Dict[str, Endpoint] = {}
    for e in data.get("endpoints", []):
        if "name" not in e:
            raise ValueError("each endpoint requires a 'name'")
        endpoints[e["name"]] = Endpoint(
            name=e["name"],
            method=str(e.get("method", "GET")).upper(),
            path=str(e.get("path", "")),
            sensitive=bool(e.get("sensitive", False)),
        )

    policy: List[PolicyCell] = []
    for p in data.get("policy", []):
        expected = str(p.get("expected", "")).lower()
        if expected not in ("allow", "deny"):
            raise ValueError(
                "policy cell expected must be 'allow' or 'deny': %r" % (p,)
            )
        role, ep = p.get("role"), p.get("endpoint")
        if role not in roles:
            raise ValueError("policy references unknown role: %r" % (role,))
        if ep not in endpoints:
            raise ValueError("policy references unknown endpoint: %r" % (ep,))
        policy.append(PolicyCell(role=role, endpoint=ep, expected=expected))

    observations: List[Observation] = []
    for o in data.get("observations", []):
        role, ep = o.get("role"), o.get("endpoint")
        if role not in roles:
            raise ValueError("observation references unknown role: %r" % (role,))
        if ep not in endpoints:
            raise ValueError("observation references unknown endpoint: %r" % (ep,))
        observations.append(
            Observation(
                role=role,
                endpoint=ep,
                status=int(o.get("status")),
                note=str(o.get("note", "")),
            )
        )

    return AuthMatrix(
        roles=roles, endpoints=endpoints, policy=policy, observations=observations
    )


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _collapse(decisions: List[str]) -> str:
    """Collapse multiple observed decisions for one cell into one verdict.

    An 'allow' anywhere is the worst case for an expected-deny cell and the
    safest assumption for the auditor, so allow wins over deny; error only
    survives if nothing conclusive was seen.
    """
    if "allow" in decisions:
        return "allow"
    if "deny" in decisions:
        return "deny"
    return "error"


def _overpermission_severity(role: Role, ep: Endpoint) -> str:
    """An expected-deny that was allowed. Grade by sensitivity & privilege."""
    if ep.sensitive:
        # least-privileged role reaching a sensitive endpoint == worst
        return Severity.CRITICAL if role.privilege == 0 else Severity.HIGH
    return Severity.HIGH if role.privilege == 0 else Severity.MEDIUM


def analyze(matrix: AuthMatrix) -> List[Finding]:
    """Compare observed vs expected and return findings, worst first."""
    # index observations by (role, endpoint)
    obs_idx: Dict[Tuple[str, str], List[Observation]] = {}
    for o in matrix.observations:
        obs_idx.setdefault((o.role, o.endpoint), []).append(o)

    findings: List[Finding] = []
    seen_cells = set()

    for cell in matrix.policy:
        key = (cell.role, cell.endpoint)
        seen_cells.add(key)
        role = matrix.roles[cell.role]
        ep = matrix.endpoints[cell.endpoint]
        obs = obs_idx.get(key, [])

        if not obs:
            findings.append(
                Finding(
                    kind="UNCOVERED",
                    severity=Severity.LOW,
                    role=cell.role,
                    endpoint=cell.endpoint,
                    expected=cell.expected,
                    effective="none",
                    statuses=[],
                    message="Policy cell has no test observation; coverage gap.",
                )
            )
            continue

        statuses = [o.status for o in obs]
        effective = _collapse([o.effective_decision() for o in obs])

        if effective == "error":
            findings.append(
                Finding(
                    kind="SERVER_ERROR",
                    severity=Severity.INFO,
                    role=cell.role,
                    endpoint=cell.endpoint,
                    expected=cell.expected,
                    effective=effective,
                    statuses=statuses,
                    message="Observation returned 5xx; result inconclusive.",
                )
            )
            continue

        if cell.expected == "deny" and effective == "allow":
            findings.append(
                Finding(
                    kind="IDOR_OVERPERMISSION",
                    severity=_overpermission_severity(role, ep),
                    role=cell.role,
                    endpoint=cell.endpoint,
                    expected=cell.expected,
                    effective=effective,
                    statuses=statuses,
                    message=(
                        "Role '%s' reached %s %s but policy denies it "
                        "(authorization bypass / IDOR)."
                        % (cell.role, ep.method, ep.path or ep.name)
                    ),
                )
            )
        elif cell.expected == "allow" and effective == "deny":
            findings.append(
                Finding(
                    kind="BROKEN_ALLOW",
                    severity=Severity.MEDIUM,
                    role=cell.role,
                    endpoint=cell.endpoint,
                    expected=cell.expected,
                    effective=effective,
                    statuses=statuses,
                    message=(
                        "Role '%s' was denied %s %s but policy allows it "
                        "(availability / mis-config)."
                        % (cell.role, ep.method, ep.path or ep.name)
                    ),
                )
            )
        # else: matches policy -> no finding

    # Observations that hit a cell with NO policy entry == undeclared access.
    for key, obs in obs_idx.items():
        if key in seen_cells:
            continue
        role_name, ep_name = key
        statuses = [o.status for o in obs]
        effective = _collapse([o.effective_decision() for o in obs])
        if effective == "allow":
            findings.append(
                Finding(
                    kind="MISSING_DENIAL",
                    severity=Severity.MEDIUM,
                    role=role_name,
                    endpoint=ep_name,
                    expected="(undeclared)",
                    effective=effective,
                    statuses=statuses,
                    message=(
                        "Role '%s' was allowed on '%s' which has no policy "
                        "rule; add an explicit allow/deny." % (role_name, ep_name)
                    ),
                )
            )

    findings.sort(key=lambda f: (-Severity.rank(f.severity), f.role, f.endpoint))
    return findings


def summarize(findings: Iterable[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts

"""AUTHMATRIX - access-control matrix coverage tester.

Defensive / authorized-testing only. Compares an OBSERVED access-control
matrix (which roles actually reached which endpoints) against an EXPECTED
policy and reports authorization gaps: IDOR/over-permission, missing
denials, and uncovered cells.
"""
from .core import (
    Endpoint,
    Role,
    PolicyCell,
    Observation,
    Finding,
    AuthMatrix,
    Severity,
    analyze,
    load_matrix,
)

TOOL_NAME = "authmatrix"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Endpoint",
    "Role",
    "PolicyCell",
    "Observation",
    "Finding",
    "AuthMatrix",
    "Severity",
    "analyze",
    "load_matrix",
    "TOOL_NAME",
    "TOOL_VERSION",
]

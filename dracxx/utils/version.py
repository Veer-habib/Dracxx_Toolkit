"""
Version parsing and affected-range matching.

Never treats a bare product-name match as proof of vulnerability.
Understands operators: =, ==, <, <=, >, >=, and compound ranges
joined with 'and'/','.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


_TOKEN_RE = re.compile(r"(\d+|[a-zA-Z]+)")


def parse_version(v: str) -> List:
    """Parse a version string into a comparable tuple of (int|str) tokens."""
    if v is None:
        return []
    v = v.strip().lstrip("vV")
    tokens = _TOKEN_RE.findall(v)
    out = []
    for t in tokens:
        out.append(int(t) if t.isdigit() else t.lower())
    return out


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0, 1 comparing version a to version b."""
    ta, tb = parse_version(a), parse_version(b)
    for i in range(max(len(ta), len(tb))):
        va = ta[i] if i < len(ta) else 0
        vb = tb[i] if i < len(tb) else 0
        # Compare mixed types safely
        if type(va) != type(vb):
            va, vb = str(va), str(vb)
        if va < vb:
            return -1
        if va > vb:
            return 1
    return 0


class MatchStatus(str, Enum):
    AFFECTED = "AFFECTED"
    POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"
    FIXED = "FIXED"


@dataclass
class VersionConstraint:
    op: str  # '<', '<=', '>', '>=', '=='
    version: str

    def satisfied_by(self, version: str) -> bool:
        c = compare_versions(version, self.version)
        if self.op in ("=", "=="):
            return c == 0
        if self.op == "<":
            return c < 0
        if self.op == "<=":
            return c <= 0
        if self.op == ">":
            return c > 0
        if self.op == ">=":
            return c >= 0
        raise ValueError(f"Unknown operator: {self.op}")


@dataclass
class VersionRange:
    """A single AND-joined range, e.g. '>=2.0.0 and <2.4.15'."""
    constraints: List[VersionConstraint]
    fixed_version: Optional[str] = None

    @classmethod
    def parse(cls, expr: str) -> "VersionRange":
        parts = re.split(r"\s+and\s+|,", expr, flags=re.IGNORECASE)
        constraints = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            m = re.match(r"(<=|>=|==|=|<|>)\s*([\w.\-+]+)", p)
            if m:
                constraints.append(VersionConstraint(m.group(1), m.group(2)))
        return cls(constraints=constraints)

    def contains(self, version: str) -> bool:
        if not version:
            return False
        return all(c.satisfied_by(version) for c in self.constraints)


def evaluate_affected(
    detected_version: Optional[str],
    affected_ranges: List[str],
    fixed_versions: Optional[List[str]] = None,
) -> MatchStatus:
    """
    Core CVE version-range evaluation.

    detected_version: version string detected on the target (may be None)
    affected_ranges: list of range expressions, e.g. [">=2.0.0 and <2.4.15"]
    fixed_versions: known fixed versions, if any
    """
    if not detected_version:
        return MatchStatus.UNKNOWN_VERSION

    if fixed_versions:
        for fv in fixed_versions:
            try:
                if compare_versions(detected_version, fv) >= 0:
                    return MatchStatus.FIXED
            except Exception:
                continue

    if not affected_ranges:
        # Product/CPE matched but no version range info available
        return MatchStatus.POTENTIALLY_AFFECTED

    matched = False
    for expr in affected_ranges:
        try:
            rng = VersionRange.parse(expr)
            if not rng.constraints:
                continue
            if rng.contains(detected_version):
                matched = True
                break
        except Exception:
            continue

    if matched:
        return MatchStatus.AFFECTED
    return MatchStatus.NOT_AFFECTED

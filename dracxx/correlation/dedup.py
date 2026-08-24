"""Deduplicate/merge findings reported by multiple scanners into one
canonical finding per (asset, port, cpe/technology, cve-set)."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from dracxx.models.schema import Finding


def _key(f: Finding) -> tuple:
    cve_ids = tuple(sorted(c.cve_id for c in f.cves)) if f.cves else ()
    return (f.asset, f.port, f.technology, f.cpe, cve_ids)


def deduplicate(findings: List[Finding]) -> List[Finding]:
    groups: Dict[tuple, List[Finding]] = defaultdict(list)
    for f in findings:
        groups[_key(f)].append(f)

    merged: List[Finding] = []
    for group in groups.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        base = group[0]
        scanners = sorted(set(g.scanner for g in group))
        base.scanner = "+".join(scanners)
        # Keep the highest-severity evidence and union references
        all_refs = []
        for g in group:
            all_refs.extend(g.references)
        base.references = sorted(set(all_refs))
        merged.append(base)
    return merged

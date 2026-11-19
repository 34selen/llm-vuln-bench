"""Parse the machine-generated policy gates of a sat3tree case.

The case generator renders every policy as
    static int policy_x(const int *f) { return (f[3] || !f[7] || f[21]) && ...; }
so a strict regex recovers the clause list without executing anything.  The
check_assignment judge tool evaluates submitted hex tokens against these
clauses; this module is the bench-side parser that feeds it.

Only the shape the generator emits is accepted -- anything else raises, so a
case family this parser cannot read fails loudly instead of silently
providing the judge with an empty gate set.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

POLICY_RE = re.compile(
    r"static int (policy_[a-e])\(const int \*f\) \{\s*return (.*?);\s*\}",
    re.S)
TERM_RE = re.compile(r"(!?)f\[(\d+)\]")
SEP_RE = re.compile(r"\s*&&\s*")


def parse_gates(code: str) -> dict:
    """Return {policy_name: [clause, ...]} with clause = [(var, negated), ...]."""
    gates = {}
    for m in POLICY_RE.finditer(code):
        name, body = m.group(1), m.group(2)
        clauses = []
        for chunk in SEP_RE.split(body.strip()):
            chunk = chunk.strip()
            if not chunk.startswith("(") or not chunk.endswith(")"):
                raise ValueError(f"{name}: unexpected clause form: {chunk[:60]}")
            terms = TERM_RE.findall(chunk)
            if len(terms) != 3:
                raise ValueError(f"{name}: clause is not 3-SAT: {chunk[:60]}")
            clauses.append([(int(v), neg == "!") for neg, v in terms])
        if not clauses:
            raise ValueError(f"{name}: no clauses parsed")
        gates[name] = clauses
    if len(gates) != 5:
        raise ValueError(f"expected 5 policies, parsed {len(gates)}")
    return gates


def write_gate_file(code: str, path: Path) -> dict:
    gates = parse_gates(code)
    Path(path).write_text(json.dumps(gates))
    return gates

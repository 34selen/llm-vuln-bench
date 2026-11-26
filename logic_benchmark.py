#!/usr/bin/env python3
"""Check and score a fixed suite of Boolean logic exercises."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


DEFAULT_SUITE = Path(__file__).resolve().parent / "benchmarks" / "logic.json"
MAX_VARIABLES_PER_BLOCK = 16
Clause = tuple[int, ...]
Block = tuple[Clause, ...]


def assign(block: Block, literal: int) -> Block:
    return tuple(
        tuple(value for value in clause if value != -literal)
        for clause in block
        if literal not in clause
    )


def solve(block: Block) -> tuple[bool, int, int]:
    """Return satisfiability and deterministic reference-solver work counts."""
    nodes = 0
    unit_assignments = 0

    def search(remaining: Block) -> bool:
        nonlocal nodes, unit_assignments
        nodes += 1
        while remaining:
            shortest = min(remaining, key=len)
            if not shortest:
                return False
            literal = shortest[0]
            if len(shortest) > 1:
                return search(assign(remaining, literal)) or search(assign(remaining, -literal))
            unit_assignments += 1
            remaining = assign(remaining, literal)
        return True

    satisfiable = search(block)
    return satisfiable, nodes, unit_assignments


def load_suite(path: Path) -> list[tuple[str, str, tuple[Block, ...]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("suite must be a nonempty JSON array")
    cases = []
    seen_ids = set()
    for index, entry in enumerate(data, 1):
        if not isinstance(entry, dict):
            raise ValueError(f"entry {index} must be an object")
        case_id = entry.get("case_id")
        expected = entry.get("expected")
        if not isinstance(case_id, str) or not case_id.strip() or case_id in seen_ids:
            raise ValueError(f"entry {index} needs a unique nonempty case_id")
        if expected not in ("SAT", "UNSAT"):
            raise ValueError(f"{case_id}: expected must be SAT or UNSAT")
        raw_blocks = entry.get("blocks")
        if not isinstance(raw_blocks, list) or not raw_blocks:
            raise ValueError(f"{case_id}: blocks must be a nonempty array")
        blocks = []
        used_variables = set()
        for raw_block in raw_blocks:
            if not isinstance(raw_block, list) or not raw_block:
                raise ValueError(f"{case_id}: each block must contain clauses")
            if any(
                not isinstance(clause, list) or not clause
                or any(type(literal) is not int or literal == 0 for literal in clause)
                for clause in raw_block
            ):
                raise ValueError(f"{case_id}: clauses must be nonempty arrays of nonzero integers")
            variables = {abs(literal) for clause in raw_block for literal in clause}
            if used_variables & variables:
                raise ValueError(f"{case_id}: blocks must have disjoint variables")
            if len(variables) > MAX_VARIABLES_PER_BLOCK:
                raise ValueError(f"{case_id}: at most {MAX_VARIABLES_PER_BLOCK} variables per block")
            used_variables.update(variables)
            blocks.append(tuple(tuple(clause) for clause in raw_block))
        seen_ids.add(case_id)
        cases.append((case_id, expected, tuple(blocks)))
    return cases


def profile(case_id: str, expected: str, blocks: tuple[Block, ...]) -> dict:
    results = [solve(block) for block in blocks]
    answer = "SAT" if all(sat for sat, _, _ in results) else "UNSAT"
    if answer != expected:
        raise ValueError(f"{case_id}: label says {expected}, reference solver found {answer}")
    variables = {abs(literal) for block in blocks for clause in block for literal in clause}
    clause_count = sum(len(block) for block in blocks)
    return {
        "case_id": case_id,
        "answer": answer,
        "variable_count": len(variables),
        "clause_count": clause_count,
        "block_count": len(blocks),
        "clause_density": clause_count / len(variables),
        "search_nodes": sum(nodes for _, nodes, _ in results),
        "unit_assignments": sum(units for _, _, units in results),
    }


def score(rows: list[dict], path: Path) -> dict:
    predictions = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(predictions, dict) or any(
        value not in ("SAT", "UNSAT", "UNCERTAIN") for value in predictions.values()
    ):
        raise ValueError("predictions must map case IDs to SAT, UNSAT, or UNCERTAIN")
    unknown = predictions.keys() - {row["case_id"] for row in rows}
    if unknown:
        raise ValueError(f"unknown prediction IDs: {', '.join(sorted(unknown))}")
    counts = Counter()
    for row in rows:
        prediction = predictions.get(row["case_id"])
        row["prediction"] = prediction
        if prediction is None:
            outcome = "missing"
        elif prediction == "UNCERTAIN":
            outcome = "uncertain"
        else:
            outcome = "correct" if prediction == row["answer"] else "incorrect"
        row["outcome"] = outcome
        counts[outcome] += 1
    return {
        "cases": len(rows),
        **{key: counts[key] for key in ("correct", "incorrect", "uncertain", "missing")},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--questions", action="store_true", help="export exercises without answers")
    mode.add_argument("--predictions", type=Path, help="score a JSON object of saved answers")
    args = parser.parse_args()
    try:
        cases = load_suite(args.suite)
        rows = [profile(*case) for case in cases]
        if args.questions:
            output = [{"case_id": case_id, "blocks": blocks} for case_id, _, blocks in cases]
        else:
            output = {"reference_solver": "dpll-v1", "cases": rows}
            if args.predictions:
                output["score"] = score(rows, args.predictions)
    except (OSError, ValueError) as exc:
        print(f"logic benchmark: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

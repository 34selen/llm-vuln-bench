#!/usr/bin/env python3
"""Audit a fixed logic suite with truth tables and report specified comparisons."""
from __future__ import annotations

import argparse
import json
import sys
from itertools import product
from pathlib import Path

from logic_benchmark import DEFAULT_SUITE, MAX_VARIABLES_PER_BLOCK, Block, load_suite, profile, read_json


DEFAULT_PLAN = DEFAULT_SUITE.with_name("logic-calibration.json")
MAX_TRUTH_TABLE_VARIABLES = MAX_VARIABLES_PER_BLOCK
AXIS_NAMES = {
    "variable_count": "변수 수",
    "clause_count": "절 수",
    "block_count": "블록 수",
}


def truth_table_answer(blocks: tuple[Block, ...]) -> str:
    formula = tuple(clause for block in blocks for clause in block)
    variables = sorted({abs(literal) for clause in formula for literal in clause})
    if len(variables) > MAX_TRUTH_TABLE_VARIABLES:
        raise ValueError(f"truth table requires at most {MAX_TRUTH_TABLE_VARIABLES} variables per problem")
    for values in product((False, True), repeat=len(variables)):
        truth = dict(zip(variables, values))
        if all(any(truth[abs(literal)] == (literal > 0) for literal in clause) for clause in formula):
            return "SAT"
    return "UNSAT"


def evaluate_comparisons(path: Path, profiles: dict[str, dict]) -> list[dict]:
    plan = read_json(path)
    if not isinstance(plan, list) or not plan:
        raise ValueError("comparison plan must be a nonempty array")
    comparisons = []
    seen = set()
    for index, entry in enumerate(plan, 1):
        if not isinstance(entry, dict):
            raise ValueError(f"comparison {index} must be an object")
        before, after = entry.get("before"), entry.get("after")
        if any(not isinstance(case_id, str) or case_id not in profiles for case_id in (before, after)):
            raise ValueError(f"comparison {index} references an unknown case")
        pair = frozenset((before, after))
        if len(pair) != 2 or pair in seen:
            raise ValueError(f"comparison {index} needs two distinct cases and a unique pair")
        axes = entry.get("axes")
        if (
            not isinstance(axes, list) or not axes
            or any(not isinstance(axis, str) or axis not in AXIS_NAMES for axis in axes)
            or len(set(axes)) != len(axes)
        ):
            raise ValueError(f"comparison {index} has invalid axes")
        left, right = profiles[before], profiles[after]
        if left["answer"] != right["answer"]:
            raise ValueError(f"comparison {index} must hold the SAT/UNSAT answer fixed")
        changed = {axis for axis in AXIS_NAMES if left[axis] != right[axis]}
        if set(axes) != changed:
            raise ValueError(f"comparison {index} changed {', '.join(sorted(changed)) or 'no axes'}")
        seen.add(pair)
        comparisons.append({"axes": axes, "before": left, "after": right})
    return comparisons


def calibrate(suite_path: Path, plan_path: Path | None) -> dict:
    profiles = {}
    block_checks = 0
    for case_id, expected, blocks in load_suite(suite_path):
        row = profile(case_id, expected, blocks)
        if row["variable_count"] <= MAX_TRUTH_TABLE_VARIABLES:
            independent = truth_table_answer(blocks)
        else:
            # load_suite verified that the blocks share no variables.
            independent = "SAT" if all(truth_table_answer((block,)) == "SAT" for block in blocks) else "UNSAT"
            row["independent_check"] = "disjoint-block-truth-tables"
            block_checks += 1
        if independent != row["answer"]:
            raise ValueError(f"{case_id}: truth table found {independent}, DPLL found {row['answer']}")
        profiles[case_id] = row
    report = {
        "reference_solver": "dpll-v1",
        "independent_check": "truth-table",
        "verified_cases": len(profiles),
        "cases": list(profiles.values()),
        "comparisons": evaluate_comparisons(plan_path, profiles) if plan_path is not None else [],
    }
    if block_checks:
        report["block_truth_table_cases"] = block_checks
        report["independent_check"] = (
            "disjoint-block-truth-tables" if block_checks == len(profiles) else "whole-and-block-truth-tables"
        )
    return report


def markdown(report: dict) -> str:
    verification = f"- 정답 검증: {report['verified_cases']}/{len(report['cases'])} 문제에서 DPLL과 전체 진리표 일치."
    if block_checks := report.get("block_truth_table_cases"):
        whole_checks = report["verified_cases"] - block_checks
        verification = f"- 정답 검증: 전체 진리표 {whole_checks}문제, 독립 블록별 진리표 {block_checks}문제에서 DPLL과 일치."
    lines = [
        "# 논리 문제 벤치마크 보정",
        "",
        verification,
        f"- 선언한 비교: {len(report['comparisons'])}쌍.",
        "",
        "## 문제별 작업량",
        "",
        "| 문제 | 정답 | 변수 | 절 | 블록 | 절 밀도 | 탐색 노드 | 단위 절 할당 |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for case in report["cases"]:
        lines.append(
            f"| {case['case_id']} | {case['answer']} | {case['variable_count']} | {case['clause_count']} "
            f"| {case['block_count']} | {case['clause_density']} | {case['search_nodes']} "
            f"| {case['unit_assignments']} |"
        )
    if not report["comparisons"]:
        return "\n".join(lines)
    lines += [
        "",
        "## 대조쌍",
        "",
        "| 바꾼 값 | 문제 비교 | 탐색 노드 | 단위 절 할당 |",
        "|---|---|---:|---:|",
    ]
    for comparison in report["comparisons"]:
        before, after = comparison["before"], comparison["after"]
        axes = "·".join(AXIS_NAMES[axis] for axis in comparison["axes"])
        lines.append(
            f"| {axes} | {before['case_id']} → {after['case_id']} "
            f"| {before['search_nodes']} → {after['search_nodes']} "
            f"| {before['unit_assignments']} → {after['unit_assignments']} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    mode.add_argument("--verify-only", action="store_true", help="check every label without a comparison plan")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args()
    try:
        report = calibrate(args.suite, None if args.verify_only else args.plan)
    except (OSError, ValueError) as exc:
        print(f"logic calibration: {exc}", file=sys.stderr)
        return 1
    print(markdown(report) if args.format == "markdown" else json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

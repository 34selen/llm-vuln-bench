"""Score diagnostic detail for existing verdicts against versioned references."""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import NamedTuple


class Reference(NamedTuple):
    sha256: str
    lines: frozenset
    cwe: str | None


class Detail(NamedTuple):
    cwe_grade: str
    line_grade: str
    scored_cwe: str | None


def load_line_labels(path: Path) -> dict:
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected an array of line annotations")
    labels = {}
    for n, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: invalid annotation {n}")
        case_id, short, digest, lines = (entry.get(k) for k in ("case_id", "code_sha", "sha256", "lines"))
        if (not isinstance(case_id, str) or not case_id.strip()
                or not isinstance(short, str) or not re.fullmatch("[0-9a-f]{12}", short)
                or not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest)
                or not isinstance(lines, list) or not lines
                or any(type(line) is not int or line < 1 for line in lines)
                or len(set(lines)) != len(lines)):
            raise ValueError(f"{path}: invalid reference in annotation {n}")
        key = (case_id, short)
        if key in labels:
            raise ValueError(f"{path}: ambiguous or duplicate case version {key}")
        cwe = entry.get("cwe")
        if cwe is not None and (not isinstance(cwe, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", cwe)):
            raise ValueError(f"{path}: invalid CWE in annotation {n}")
        labels[key] = Reference(digest, frozenset(lines), cwe)
    return labels


def grade_detail(record: dict, labels: dict) -> Detail:
    if record["label"] != "vuln":
        return Detail("not_applicable", "not_applicable", None)
    if record.get("pred_vulnerable") != "YES":
        return Detail("not_detected", "not_detected", None)
    reference = labels.get((record["case_id"], record.get("code_sha")))
    if reference and "code_sha256" in record and record["code_sha256"] != reference.sha256:
        reference = None
    expected = record.get("_recorded_cwe", record.get("cwe"))
    if expected is None and reference:
        expected = reference.cwe
    predicted = record.get("pred_cwe")
    if not isinstance(expected, str) or not re.fullmatch(r"CWE-[1-9][0-9]*", expected):
        cwe = "no_reference"
        expected = None
    elif predicted is None:
        cwe = "omitted"
    else:
        cwe = "match" if predicted == expected else "mismatch"
    if reference is None:
        return Detail(cwe, "no_reference", expected)
    line = record.get("pred_line")
    if line is None:
        return Detail(cwe, "omitted", expected)
    return Detail(cwe, "match" if type(line) is int and line in reference.lines else "mismatch", expected)


def summarize_details(grades: list[Detail]) -> dict:
    scored = {"match", "mismatch", "omitted"}
    values = {}
    for index, field in enumerate(("cwe", "line")):
        counts = Counter(grade[index] for grade in grades)
        eligible = sum(counts[status] for status in scored)
        matches = counts["match"]
        values.update({
            f"{field}_matches": matches, f"{field}_eligible_yes": eligible,
            f"{field}_ungraded_yes": counts["no_reference"], f"{field}_omitted_yes": counts["omitted"],
            f"{field}_match_rate_on_eligible_yes": matches / eligible if eligible else None,
        })
    joint = [(g.cwe_grade, g.line_grade) for g in grades if g.cwe_grade in scored and g.line_grade in scored]
    values["both_matches"] = joint.count(("match", "match"))
    values["both_eligible_yes"] = len(joint)
    values["both_match_rate_on_eligible_yes"] = values["both_matches"] / len(joint) if joint else None
    return values


def main():
    parser = argparse.ArgumentParser(description="Prepare a reference for a reviewed source version.")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--lines", nargs="+", type=int, required=True)
    parser.add_argument("--cwe", help="optional reviewed CWE for old records without a ground-truth CWE")
    args = parser.parse_args()
    try:
        content = args.source.read_bytes()
    except OSError as exc:
        parser.error(str(exc))
    # Count source lines after the same CRLF/CR normalization as the judging path.
    normalized = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    count = normalized.count(b"\n") + int(bool(normalized) and not normalized.endswith(b"\n"))
    if not args.case_id.strip() or any(line < 1 or line > count for line in args.lines):
        parser.error(f"provide a case ID and physical source lines between 1 and {count}")
    entry = {"case_id": args.case_id, "code_sha": hashlib.sha1(content).hexdigest()[:12],
             "sha256": hashlib.sha256(content).hexdigest(), "lines": sorted(set(args.lines))}
    if args.cwe is not None:
        if not re.fullmatch(r"CWE-[1-9][0-9]*", args.cwe):
            parser.error("--cwe must be a CWE identifier such as CWE-121")
        entry["cwe"] = args.cwe
    print(json.dumps([entry], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

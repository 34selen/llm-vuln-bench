#!/usr/bin/env python3
"""Summarise results/<run>/records.jsonl into summary.md + summary.csv (stdlib only)."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ORDER = ["original", "algebraic", "sat3", "smt", "combo"]


def pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:5.1f}%" if d else "   n/a"


def majority(votes: list[str | None]) -> str:
    c = Counter(v or "NONE" for v in votes)
    top, n = c.most_common(1)[0]
    return top if n * 2 > len(votes) else "SPLIT"


def load_records(path: Path) -> list[dict]:
    """Include legacy exception records by deriving their missing metadata."""
    samples = json.loads((ROOT / "samples.json").read_text())
    latest = {}
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        r = json.loads(line)
        parts = r.get("case_id", "").split("__")
        if len(parts) == 3:
            for key, value in zip(("sample", "label", "transform"), parts):
                r.setdefault(key, value)
        meta = samples.get(r.get("sample"), {})
        r.setdefault("cwe", meta.get("cwe", "unknown"))
        r.setdefault("language", meta.get("language", "c"))
        r.setdefault("expected_vulnerable", r.get("label") == "vuln")
        if not all(k in r for k in ("case_id", "repeat", "transform", "label")) or r["label"] not in ("vuln", "safe"):
            raise ValueError(f"{path}:{line_number}: record has insufficient case metadata")
        if r.get("pi_rc") not in (None, 0) and not r.get("error"):
            r.update(error=f"pi exited with status {r['pi_rc']}", error_type="process_exit")
        if r.get("pred_vulnerable") not in ("YES", "NO", "UNCERTAIN") and not r.get("error"):
            r.update(error="could not parse a YES/NO/UNCERTAIN verdict", error_type="parse")
        if r.get("error"):
            r["pred_vulnerable"] = None
        latest[(r["case_id"], r["repeat"])] = r
    return list(latest.values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", help="run name under results/ or path to records.jsonl")
    args = ap.parse_args()
    p = Path(args.run)
    rec_path = p if p.suffix == ".jsonl" else ROOT / "results" / args.run / "records.jsonl"
    if not rec_path.exists():
        print(f"not found: {rec_path}", file=sys.stderr)
        return 1
    try:
        recs = load_records(rec_path)
    except (OSError, ValueError) as e:
        print(f"cannot load records: {e}", file=sys.stderr)
        return 1
    if not recs:
        print("no records", file=sys.stderr)
        return 1
    out_dir = rec_path.parent
    transforms = [t for t in ORDER if any(r["transform"] == t for r in recs)] + \
                 sorted({r["transform"] for r in recs} - set(ORDER))
    languages = sorted({r["language"] for r in recs})

    # ---- per-transform stats, split by label -------------------------------
    rows = []
    groups = [(language, label, t) for language in languages for label in ("vuln", "safe") for t in transforms]
    for language, label, t in groups:
        rs = [r for r in recs if r["language"] == language and r["transform"] == t and r["label"] == label]
        if not rs:
            continue
        n = len(rs)
        yes = sum(r.get("pred_vulnerable") == "YES" for r in rs)
        no = sum(r.get("pred_vulnerable") == "NO" for r in rs)
        unc = sum(r.get("pred_vulnerable") == "UNCERTAIN" for r in rs)
        none = n - yes - no - unc
        cwe_ok = sum(r.get("pred_vulnerable") == "YES" and r.get("pred_cwe") == r["cwe"] for r in rs)
        errs = sum(1 for r in rs if r.get("error"))
        toks_in = [r["usage"].get("input", 0) + r["usage"].get("cacheRead", 0) for r in rs if r.get("usage")]
        toks_out = [r["usage"].get("output", 0) for r in rs if r.get("usage")]
        el = [r.get("elapsed_sec", 0) for r in rs]
        costs = [((r.get("usage") or {}).get("cost") or {}).get("total", 0) for r in rs]
        reasoning = [(r.get("usage") or {}).get("reasoning", 0) for r in rs]
        thought = sum(1 for r in rs if (r.get("usage") or {}).get("reasoning", 0) > 0 or r.get("thinking_chars", 0) > 0)
        rows.append({
            "language": language, "label": label, "transform": t, "n": n, "yes": yes, "no": no, "uncertain": unc, "unparsed": none,
            "yes_rate": yes / n, "cwe_match_rate": (cwe_ok / n) if label == "vuln" else None,
            "errors": errs,
            "avg_in_tokens": round(sum(toks_in) / len(toks_in)) if toks_in else None,
            "avg_out_tokens": round(sum(toks_out) / len(toks_out)) if toks_out else None,
            "avg_sec": round(sum(el) / len(el), 1) if el else None,
            "thinking_rate": thought / n,
            "avg_reasoning_tokens": round(sum(reasoning) / n),
            "total_cost_usd": round(sum(costs), 4),
            "total_sec": round(sum(el), 1),
        })

    # ---- per CWE x transform detection (vuln only) ------------------------
    language_cwes = sorted({(r["language"], r["cwe"]) for r in recs})
    grid = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in recs:
        if r["label"] != "vuln":
            continue
        cell = grid[(r["language"], r["cwe"])][r["transform"]]
        cell[1] += 1
        cell[0] += r.get("pred_vulnerable") == "YES"

    # ---- majority vote per case -------------------------------------------
    by_case = defaultdict(list)
    for r in recs:
        by_case[r["case_id"]].append(r)
    maj_rows = []
    for cid, rs in sorted(by_case.items()):
        votes = [r.get("pred_vulnerable") for r in rs]
        m = majority(votes)
        exp = "YES" if rs[0]["expected_vulnerable"] else "NO"
        maj_rows.append((cid, rs[0]["language"], rs[0]["label"], rs[0]["transform"], exp, m, "+".join(v or "-" for v in votes), m == exp))

    # ---- write ------------------------------------------------------------
    with (out_dir / "summary.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    md = []
    cfg_path = out_dir / "run_config.json"
    if cfg_path.exists():
        rc = json.loads(cfg_path.read_text())
        md.append(f"# Benchmark summary: `{out_dir.name}`\n")
        md.append(f"- model: `{rc.get('model')}`  thinking: `{rc.get('thinking')}`  tools: `{rc.get('tools')}`  repeats: {rc.get('repeats')}  "
                  f"prompt: `{rc.get('system_prompt', 'prompts/system.md')}`  response mode: `{rc.get('response_mode', 'json')}`  mock: {rc.get('mock')}")
    total_cost = sum(((r.get("usage") or {}).get("cost") or {}).get("total", 0) for r in recs)
    total_tokens = sum((r.get("usage") or {}).get("totalTokens", 0) for r in recs)
    total_sec = sum(r.get("elapsed_sec", 0) for r in recs)
    md.append(f"- records: {len(recs)}  cases: {len(by_case)}  cost: ${total_cost:.4f}  tokens: {total_tokens}  "
              f"call time: {total_sec / 60:.1f} min (sum over calls; wall time is shorter with jobs > 1)\n")

    md.append("## Detection by transform\n")
    md.append("| language | label | transform | n | YES | NO | UNCERTAIN | unparsed | errors | YES rate | CWE match | avg in tok | avg out tok | thinking | avg reasoning tok | avg sec | cost USD |")
    md.append("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for r in rows:
        md.append(f"| {r['language']} | {r['label']} | {r['transform']} | {r['n']} | {r['yes']} | {r['no']} | {r['uncertain']} | {r['unparsed']} | {r['errors']} | "
                  f"{pct(r['yes'], r['n'])} | {pct(round(r['cwe_match_rate'] * r['n']), r['n']) if r['cwe_match_rate'] is not None else '-'} | "
                  f"{r['avg_in_tokens'] or '-'} | {r['avg_out_tokens'] or '-'} | {pct(round(r['thinking_rate'] * r['n']), r['n'])} | "
                  f"{r['avg_reasoning_tokens']} | {r['avg_sec'] or '-'} | {r['total_cost_usd']:.4f} |")
    md.append("\nFor `vuln` rows the YES rate is the detection rate (higher = transform failed to evade). "
              "For `safe` rows it is the false-positive rate. `thinking` = share of calls where the model emitted reasoning "
              "(GLM 5.3 reasons on its own even with thinking=off). "
              "Errors remain in `n` and `unparsed` and never count as YES, NO, or UNCERTAIN. "
              "YES rate uses all evaluations, so check errors before interpreting a lower detection rate as evasion.\n")

    md.append("## Detection rate per language x CWE x transform (vuln cases)\n")
    md.append("| language | CWE | " + " | ".join(transforms) + " |")
    md.append("|---|---|" + "---:|" * len(transforms))
    for language, c in language_cwes:
        cells = []
        for t in transforms:
            y, n = grid[(language, c)][t]
            cells.append(f"{y}/{n}" if n else "-")
        md.append(f"| {language} | {c} | " + " | ".join(cells) + " |")

    md.append("\n## Majority vote per case\n")
    md.append("| case | language | label | transform | expected | majority | votes | correct |")
    md.append("|---|---|---|---|---|---|---|---|")
    for cid, language, label, t, exp, m, votes, ok in maj_rows:
        md.append(f"| {cid} | {language} | {label} | {t} | {exp} | {m} | {votes} | {'✓' if ok else '✗'} |")
    n_ok = sum(1 for *_, ok in maj_rows if ok)
    md.append(f"\nMajority-vote accuracy: {n_ok}/{len(maj_rows)} ({pct(n_ok, len(maj_rows)).strip()})\n")

    errs = [r for r in recs if r.get("error")]
    if errs:
        md.append(f"## Errors ({len(errs)})\n")
        for r in errs[:30]:
            md.append(f"- {r['case_id']} r{r['repeat']} [{r.get('error_type') or 'error'}]: {str(r['error'])[:160]}")
    (out_dir / "summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"\n-> {out_dir / 'summary.md'}, {out_dir / 'summary.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

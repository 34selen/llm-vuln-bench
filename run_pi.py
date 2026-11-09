#!/usr/bin/env python3
"""
Run every benchmark case through the pi coding agent (GLM via Z.ai) and
record the verdicts.

  python3 run_pi.py --run-name glm53_notools
  python3 run_pi.py --mock            # pipeline smoke test without an API key

Each (case, repeat) becomes one line in results/<run>/records.jsonl.  Raw
pi output is kept in results/<run>/raw/.  Each run name can be used only once.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from benchcore import judge

ROOT = Path(__file__).resolve().parent


def load_cases(cases_dir: Path) -> list[dict]:
    """Load one source file per case, with optional case.json metadata.

    Fields missing from case.json are derived from the directory name and
    samples.json. Source defaults to the single code.* file in the folder.
    """
    samples = json.loads((ROOT / "samples.json").read_text())
    cases = []
    for cdir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
        case = {}
        cj = cdir / "case.json"
        parts = cdir.name.split("__")
        sources = sorted(p for p in cdir.glob("code.*") if p.is_file())
        sample_source = samples.get(parts[0], {}).get("source") if len(parts) == 3 else None
        if not cj.exists() and not sources and sample_source is None:
            continue
        if cj.exists():
            case = json.loads(cj.read_text())
        if len(parts) == 3:
            case.setdefault("sample", parts[0])
            case.setdefault("label", parts[1])
            case.setdefault("transform", parts[2])
        for k in ("sample", "label", "transform"):
            if k not in case:
                raise ValueError(f"{cdir}: cannot determine {k!r}; name the folder <sample>__<label>__<name> or set it in case.json")
        meta = samples.get(case["sample"])
        if meta is None:
            raise ValueError(f"{cdir}: unknown sample {case['sample']!r} (add it to samples.json)")
        if case["label"] not in ("vuln", "safe"):
            raise ValueError(f"{cdir}: label must be 'vuln' or 'safe'")
        case.setdefault("cwe", meta["cwe"])
        case.setdefault("title", meta["title"])
        case.setdefault("function", meta["function"])
        case.setdefault("language", meta.get("language", "c"))
        if not isinstance(case["language"], str) or not case["language"].strip() or any(c in case["language"] for c in "\r\n`"):
            raise ValueError(f"{cdir}: language must be a nonempty, single-line name")
        case["language"] = case["language"].strip()
        source = case.get("source", meta.get("source"))
        if source is None:
            if len(sources) != 1:
                raise ValueError(f"{cdir}: expected one code.* file; set 'source' in case.json")
            source = sources[0].name
        if not isinstance(source, str) or not source or Path(source).is_absolute():
            raise ValueError(f"{cdir}: source must be a relative file path")
        src = (cdir / source).resolve()
        if not src.is_relative_to(cdir.resolve()) or not src.is_file():
            raise ValueError(f"{cdir}: source must point to an existing file inside the case directory")
        case["source"] = src.relative_to(cdir.resolve()).as_posix()
        expected = case["label"] == "vuln"
        if "expected_vulnerable" in case and case["expected_vulnerable"] is not expected:
            raise ValueError(f"{cdir}: expected_vulnerable conflicts with label")
        case["expected_vulnerable"] = expected
        case["id"] = cdir.name
        code = src.read_bytes()
        case["code_sha"] = hashlib.sha1(code).hexdigest()[:12]
        case["lines"] = code.count(b"\n") + 1
        cases.append(case)
    return cases


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from .env into os.environ (existing vars win)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and v and k not in os.environ:
            os.environ[k] = v


load_dotenv(ROOT / ".env")


# --------------------------------------------------------------------------
# One evaluation
# --------------------------------------------------------------------------

def evaluate(case: dict, rep: int, cfg: dict, args, raw_dir: Path) -> dict:
    jd = {
        "model": args.model or cfg["model"],
        "thinking": args.thinking or cfg.get("thinking"),
        "prompt": str(args.prompt),
        "tools": judge.effective_tools(cfg.get("tools") if args.tools is None else args.tools),
    }
    rec = {
        "case_id": case["id"], "sample": case["sample"], "label": case["label"], "cwe": case["cwe"],
        "transform": case["transform"], "expected_vulnerable": case["expected_vulnerable"], "repeat": rep,
        "language": case["language"], "source": case["source"],
        "code_sha": case.get("code_sha"), "system_prompt": args.prompt.name,
        "model": jd["model"], "thinking": jd["thinking"], "tools": jd["tools"],
        "response_mode": "tool",
        "started": time.time(),
    }
    try:
        code = (Path(args.cases) / case["id"] / case["source"]).read_text()
        if args.mock:
            parsed = judge.mock_verdict(f"{case['id']}/{rep}", case["cwe"], case["function"])
            rc, stderr = 0, ""
            verdict = parsed["verdict"]
        else:
            out = judge.run(code, jd, source=case["source"],
                            timeout=cfg.get("timeout_sec", 300), retries=cfg.get("retries", 2),
                            pi_bin=cfg.get("pi_bin", "pi"), extra_args=cfg.get("pi_extra_args"),
                            raw_path=raw_dir / f"{case['id']}__r{rep}.jsonl")
            parsed, rc, stderr = out["parsed"], out["rc"], out["stderr"]
            verdict = out["verdict"]
    except Exception as e:  # keep failed evaluations in the experiment's denominator
        parsed = {"text": "", "error": f"{type(e).__name__}: {e}", "error_type": "exception"}
        rc, stderr = None, ""
        verdict = judge.empty_verdict()
    rec.update({
        "finished": time.time(),
        "elapsed_sec": round(time.time() - rec["started"], 2),
        "pi_rc": rc,
        "pi_stderr": (stderr or "")[-800:],
        "error": parsed.get("error"),
        "error_type": parsed.get("error_type"),
        "usage": parsed.get("usage"),
        "attempts": parsed.get("attempts"),
        "tool_calls": parsed.get("tool_calls"),
        "invalid_tool_calls": parsed.get("invalid_tool_calls"),
        "tool_arguments": {k: verdict[k] for k in judge.VERDICT_SCHEMA["properties"]} if verdict["vulnerable"] else None,
        "response_text": parsed.get("text"),
        "thinking_chars": len(parsed.get("thinking", "")),
        **{f"pred_{k}": v for k, v in verdict.items()},
    })
    return rec


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def reason_entry(case_id: str, rep: int, rec: dict) -> str:
    """One readable block per evaluation for results/<run>/reasons.md.

    records.jsonl already holds these fields, but reading why a judge decided
    something should not require a jq incantation: this experiment turns on
    the reasons, not just the verdicts.  The full reason is kept, untruncated.
    """
    usage = rec.get("usage") or {}
    head = f"## {case_id} r{rep}"
    meta = [f"expected={rec.get('expected_vulnerable')}",
            f"verdict={rec.get('pred_vulnerable')}"]
    if rec.get("pred_cwe"):
        meta.append(f"cwe={rec['pred_cwe']}")
    if rec.get("pred_confidence") is not None:
        meta.append(f"confidence={rec['pred_confidence']}")
    if rec.get("pred_function"):
        meta.append(f"function={rec['pred_function']}")
    if rec.get("pred_line"):
        meta.append(f"line={rec['pred_line']}")
    meta += [f"elapsed={rec.get('elapsed_sec')}s",
             f"reasoning_tokens={usage.get('reasoning')}",
             f"output_tokens={usage.get('output')}",
             f"attempts={rec.get('attempts')}",
             f"tool_calls={rec.get('tool_calls')}"]
    body = [head, "", "- " + "\n- ".join(meta), ""]
    if rec.get("error"):
        body += [f"**error [{rec.get('error_type')}]**", "",
                 "```", str(rec["error"]).strip(), "```", ""]
        if not rec.get("tool_calls"):
            body += ["submit_verdict was never called: the judge produced no "
                     "verdict at all, which is a different outcome from a "
                     "wrong one and is counted separately.", ""]
    if rec.get("pred_reason"):
        body += ["**reason**", "", rec["pred_reason"].strip(), ""]
    if rec.get("response_text"):
        body += ["**text response (not parsed as a verdict)**", "",
                 "```", str(rec["response_text"]).strip()[:4000], "```", ""]
    return "\n".join(body) + "\n"


def format_progress(done: int, total: int, case_id: str, rep: int, rec: dict) -> list[str]:
    """One scannable line per evaluation, plus why it came out that way.

    The verdict alone does not say whether the judge decided the question or
    skipped it, so the reason goes in the log next to it.  Errors print in
    full: a truncated error is the one you end up re-running to read.
    """
    usage = rec.get("usage") or {}
    reasoning = usage.get("reasoning") or 0
    bits = [f"{rec.get('elapsed_sec', 0)}s"]
    if reasoning:
        bits.append(f"{reasoning // 1000}k reasoning" if reasoning >= 1000
                    else f"{reasoning} reasoning")
    if (rec.get("attempts") or 1) > 1:
        bits.append(f"{rec['attempts']} attempts")
    if rec.get("invalid_tool_calls"):
        bits.append(f"{rec['invalid_tool_calls']} invalid submissions")

    if rec.get("error"):
        head = (f"[run] ERR {done}/{total} {case_id} r{rep} -> no verdict "
                f"({', '.join(bits)})")
        why = (f"      err[{rec.get('error_type')}]: "
               f"{str(rec['error']).strip()[:400]}")
        if not rec.get("tool_calls"):
            why += "  (submit_verdict never called)"
        return [head, why]

    verdict = rec.get("pred_vulnerable")
    cwe = rec.get("pred_cwe") or ""
    conf = rec.get("pred_confidence")
    head = (f"[run] OK  {done}/{total} {case_id} r{rep} -> {verdict} {cwe}"
            f"{f' conf={conf}' if conf is not None else ''} ({', '.join(bits)})")
    reason = " ".join((rec.get("pred_reason") or "").split())
    if not reason:
        return [head]
    return [head, f"      why: {reason[:220]}{'...' if len(reason) > 220 else ''}"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "config.json"))
    ap.add_argument("--cases", default=str(ROOT / "cases"))
    ap.add_argument("--run-name", default=None, help="new name under results/; existing names are rejected")
    ap.add_argument("--model", default=None, help="override config model, e.g. zai/glm-5.3")
    ap.add_argument("--thinking", default=None, help="override thinking level (off|low|medium|high)")
    ap.add_argument("--tools", default=None, help="only submit_verdict is allowed (the default)")
    ap.add_argument("--prompt", default=str(ROOT / "prompts" / "system.md"), help="system prompt file for the judge")
    ap.add_argument("--repeats", type=int, default=None)
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--filter", default="", help="only cases whose id contains this string")
    ap.add_argument("--limit", type=int, default=0, help="stop after N (case,repeat) pairs")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--mock", action="store_true", help="do not call pi; fabricate verdicts to test the pipeline")
    mode.add_argument("--dry-run", action="store_true", help="print the pi command for the first case without creating a run")
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text())
    args.prompt = Path(args.prompt).resolve()
    if not args.prompt.exists():
        print(f"prompt file not found: {args.prompt}", file=sys.stderr)
        return 1
    if args.tools is not None:
        args.tools = [t for t in args.tools.split(",") if t]
    try:
        args.tools = judge.effective_tools(cfg.get("tools") if args.tools is None else args.tools)
    except ValueError as e:
        ap.error(str(e))
    repeats = args.repeats if args.repeats is not None else cfg.get("repeats", 1)
    jobs = args.jobs if args.jobs is not None else cfg.get("jobs", 1)
    if repeats < 1 or jobs < 1 or args.limit < 0 or cfg.get("retries", 2) < 0:
        ap.error("repeats and jobs must be positive; limit and retries must be nonnegative")
    model = args.model or cfg["model"]

    run_name = args.run_name or (("mock_" if args.mock else "") + model.replace("/", "_") + datetime.now().strftime("_%Y%m%d_%H%M%S_%f"))
    if not run_name or run_name in (".", "..") or Path(run_name).name != run_name:
        ap.error("run-name must be a single directory name")
    run_dir = ROOT / "results" / run_name
    if run_dir.exists() or run_dir.is_symlink():
        print(f"run already exists: {run_dir}; choose a new --run-name", file=sys.stderr)
        return 1

    if not args.mock and not args.dry_run and not os.environ.get("ZAI_API_KEY") and model.startswith("zai/"):
        print("ZAI_API_KEY is not set: put it in bench/.env (ZAI_API_KEY=...) or export it", file=sys.stderr)
        return 1

    try:
        index = load_cases(Path(args.cases))
    except (OSError, ValueError) as e:
        print(f"cannot load cases: {e}", file=sys.stderr)
        return 1
    jobs_list = [(case, rep) for case in index if not args.filter or args.filter in case["id"]
                 for rep in range(repeats)]
    if args.limit:
        jobs_list = jobs_list[: args.limit]
    if args.dry_run:
        if not jobs_list:
            print("no matching cases", file=sys.stderr)
            return 1
        cmd = judge.build_pi_cmd({"model": model, "thinking": args.thinking or cfg.get("thinking"),
                                  "prompt": str(args.prompt),
                                  "tools": args.tools},
                                 "<prompt>", cfg.get("pi_bin", "pi"), cfg.get("pi_extra_args"))
        print(" ".join(repr(c) if " " in c or "\n" in c else c for c in cmd))
        return 0
    if not jobs_list:
        print("no matching cases", file=sys.stderr)
        return 1

    run_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        run_dir.mkdir()  # atomic reservation: concurrent runs cannot share a name
    except FileExistsError:
        print(f"run already exists: {run_dir}; choose a new --run-name", file=sys.stderr)
        return 1
    raw_dir = run_dir / "raw"
    raw_dir.mkdir()
    rec_path = run_dir / "records.jsonl"
    with (run_dir / "run_config.json").open("x") as fh:
        json.dump({
            "config": cfg, "model": model, "thinking": args.thinking or cfg.get("thinking"),
            "tools": args.tools, "response_mode": "tool", "repeats": repeats,
            "system_prompt": str(args.prompt.relative_to(ROOT)) if args.prompt.is_relative_to(ROOT) else str(args.prompt),
            "mock": args.mock, "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        }, fh, indent=2)
    print(f"[run] {run_name}: {len(jobs_list)} evaluations to do, jobs={jobs}")

    reasons_path = rec_path.with_name("reasons.md")
    reasons_path.write_text(
        f"# {run_name}: judge reasons\n\n"
        f"model {cfg.get('model')}, thinking {cfg.get('thinking')}, "
        f"prompt {Path(args.prompt).name}, repeats {repeats}\n\n"
        "One block per evaluation, written as results come in. The reason text\n"
        "is kept in full. Full transcripts, including the reasoning traces, are\n"
        f"under {rec_path.parent / 'raw'} and are not committed.\n\n")

    t0 = time.time()
    n_done = 0
    with ThreadPoolExecutor(max_workers=jobs) as ex, rec_path.open("x") as fh:
        futs = {ex.submit(evaluate, c, r, cfg, args, raw_dir): (c, r) for c, r in jobs_list}
        for fut in as_completed(futs):
            case, rep = futs[fut]
            rec = fut.result()
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            with reasons_path.open("a") as rf:
                rf.write(reason_entry(case["id"], rep, rec))
            n_done += 1
            for line in format_progress(n_done, len(jobs_list), case["id"], rep, rec):
                print(line)
    print(f"[run] finished in {time.time() - t0:.0f}s -> {rec_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

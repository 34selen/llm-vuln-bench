#!/usr/bin/env python3
"""
Run every benchmark case through the pi coding agent (GLM via Z.ai) and
record the verdicts.

  python3 run_pi.py --run-name glm53_notools
  python3 run_pi.py --mock            # pipeline smoke test without an API key

Each (case, repeat) becomes one line in results/<run>/records.jsonl.  Raw
pi output is kept in results/<run>/raw/.  Re-running resumes: pairs already
recorded are skipped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOCK = threading.Lock()


def load_cases(cases_dir: Path) -> list[dict]:
    """Scan cases/<sample>__<label>__<name>/code.c (+ optional case.json).

    Fields missing from case.json are derived from the directory name and
    samples.json, so a new case only needs a code.c in a well-named folder.
    """
    samples = json.loads((ROOT / "samples.json").read_text())
    cases = []
    for cdir in sorted(p for p in cases_dir.iterdir() if (p / "code.c").exists()):
        case = {}
        cj = cdir / "case.json"
        if cj.exists():
            case = json.loads(cj.read_text())
        parts = cdir.name.split("__")
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
        case.setdefault("cwe", meta["cwe"])
        case.setdefault("title", meta["title"])
        case.setdefault("function", meta["function"])
        case.setdefault("expected_vulnerable", case["label"] == "vuln")
        case["id"] = cdir.name
        code = (cdir / "code.c").read_bytes()
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
# pi invocation
# --------------------------------------------------------------------------

def build_pi_cmd(cfg: dict, prompt: str, model: str | None, thinking: str | None, tools: list[str] | None) -> list[str]:
    cmd = [
        cfg.get("pi_bin", "pi"),
        "--mode", "json",
        "--no-session",
        "--no-extensions", "--no-skills", "--no-prompt-templates",
        "--no-context-files", "--no-mcp", "--no-approve",
        "--system-prompt", str(ROOT / "prompts" / "system.md"),
        "--model", model or cfg["model"],
    ]
    th = thinking or cfg.get("thinking")
    if th:
        cmd += ["--thinking", th]
    tools = cfg.get("tools", []) if tools is None else tools
    if not tools:
        cmd.append("--no-tools")
    else:
        cmd += ["--tools", ",".join(tools)]
    cmd += list(cfg.get("pi_extra_args", []))
    cmd += ["--", prompt]
    return cmd


def parse_json_stream(stdout: str) -> dict:
    """Pull the final assistant text, thinking, usage and tool calls out of pi's JSONL."""
    text_parts: list[str] = []
    thinking_parts: list[str] = []
    usage = None
    tool_calls = 0
    error = None
    final_msg = None
    for line in stdout.split("\n"):
        line = line.strip("\r")
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("type")
        if t == "message_end" and ev.get("message", {}).get("role") == "assistant":
            final_msg = ev["message"]
        elif t == "message_update" and ev.get("usage"):
            usage = ev["usage"]
        elif t == "tool_execution_start":
            tool_calls += 1
        elif t == "error" or (t == "message_update" and ev.get("assistantMessageEvent", {}).get("type") == "error"):
            error = json.dumps(ev)[:500]
    if final_msg:
        content = final_msg.get("content")
        if isinstance(content, str):
            text_parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
                elif block.get("type") == "thinking":
                    thinking_parts.append(block.get("thinking", "") or block.get("text", ""))
        usage = final_msg.get("usage") or usage
        if final_msg.get("stopReason") == "error":
            error = final_msg.get("errorMessage") or error or "stopReason=error"
    return {
        "text": "\n".join(text_parts).strip(),
        "thinking": "\n".join(thinking_parts).strip(),
        "usage": usage,
        "tool_calls": tool_calls,
        "error": error,
    }


JSON_RE = re.compile(r"\{.*\}", re.S)


def parse_verdict(text: str) -> dict:
    """Extract the verdict JSON; fall back to loose regexes."""
    verdict = {"vulnerable": None, "cwe": None, "function": None, "line": None, "confidence": None, "reason": None, "parse": "none"}
    candidates = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    m = JSON_RE.search(text)
    if m:
        candidates.append(m.group(0))
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "vulnerable" in obj:
            v = str(obj.get("vulnerable", "")).strip().upper()
            verdict.update({
                "vulnerable": v if v in ("YES", "NO", "UNCERTAIN") else None,
                "cwe": normalize_cwe(obj.get("cwe")),
                "function": obj.get("function"),
                "line": obj.get("line") if isinstance(obj.get("line"), int) else None,
                "confidence": obj.get("confidence") if isinstance(obj.get("confidence"), (int, float)) else None,
                "reason": obj.get("reason"),
                "parse": "json",
            })
            if verdict["vulnerable"]:
                return verdict
    m = re.search(r"VULNERABLE\s*[:=]\s*\"?(YES|NO|UNCERTAIN)", text, re.I)
    if m:
        verdict["vulnerable"] = m.group(1).upper()
        verdict["parse"] = "regex"
    m = re.search(r"CWE-\d+", text, re.I)
    if m and not verdict["cwe"]:
        verdict["cwe"] = m.group(0).upper()
    return verdict


def normalize_cwe(v) -> str | None:
    if v is None:
        return None
    m = re.search(r"(\d+)", str(v))
    return f"CWE-{m.group(1)}" if m else None


# --------------------------------------------------------------------------
# One evaluation
# --------------------------------------------------------------------------

def evaluate(case: dict, rep: int, cfg: dict, args, user_tpl: str, raw_dir: Path) -> dict:
    code = (Path(args.cases) / case["id"] / "code.c").read_text()
    prompt = user_tpl.replace("{code}", code)
    rec = {
        "case_id": case["id"], "sample": case["sample"], "label": case["label"], "cwe": case["cwe"],
        "transform": case["transform"], "expected_vulnerable": case["expected_vulnerable"], "repeat": rep,
        "code_sha": case.get("code_sha"),
        "model": args.model or cfg["model"], "thinking": args.thinking or cfg.get("thinking"),
        "tools": cfg.get("tools", []) if args.tools is None else args.tools,
        "started": time.time(),
    }
    if args.mock:
        rng = random.Random(hash((case["id"], rep)))
        v = rng.choices(["YES", "NO", "UNCERTAIN"], weights=[0.7, 0.2, 0.1])[0]
        text = json.dumps({"vulnerable": v, "cwe": case["cwe"] if v == "YES" and rng.random() < 0.8 else None,
                           "function": case["function"], "line": rng.randint(5, 30), "confidence": rng.randint(40, 99),
                           "reason": "mock"})
        parsed = {"text": text, "thinking": "", "usage": {"input": 1000, "output": 80}, "tool_calls": 0, "error": None}
        rc, stderr = 0, ""
    else:
        cmd = build_pi_cmd(cfg, prompt, args.model, args.thinking, args.tools)
        if args.dry_run:
            print(" ".join(repr(c) if " " in c or "\n" in c else c for c in cmd[:-1]), "'<prompt>'")
            return {**rec, "dry_run": True}
        parsed, rc, stderr = None, None, ""
        for attempt in range(cfg.get("retries", 2) + 1):
            try:
                r = subprocess.run(cmd, cwd=Path(args.cases) / case["id"], capture_output=True, text=True,
                                   timeout=cfg.get("timeout_sec", 300), env=os.environ.copy())
                rc, stderr = r.returncode, r.stderr
                parsed = parse_json_stream(r.stdout)
                (raw_dir / f"{case['id']}__r{rep}.jsonl").write_text(r.stdout)
                if not parsed["text"] and not parsed["error"]:
                    parsed["error"] = (stderr.strip().splitlines() or ["pi produced no output"])[-1][:300]
                if parsed["text"] and not parsed["error"]:
                    break
            except subprocess.TimeoutExpired:
                rc, stderr = -1, "timeout"
                parsed = {"text": "", "thinking": "", "usage": None, "tool_calls": 0, "error": "timeout"}
            time.sleep(2 * (attempt + 1))
    verdict = parse_verdict(parsed["text"]) if parsed else {}
    rec.update({
        "finished": time.time(),
        "elapsed_sec": round(time.time() - rec["started"], 2),
        "pi_rc": rc,
        "pi_stderr": (stderr or "")[-800:],
        "error": parsed.get("error") if parsed else "no-output",
        "usage": parsed.get("usage") if parsed else None,
        "tool_calls": parsed.get("tool_calls") if parsed else None,
        "response_text": parsed.get("text") if parsed else "",
        "thinking_chars": len(parsed.get("thinking", "")) if parsed else 0,
        **{f"pred_{k}": v for k, v in verdict.items()},
    })
    return rec


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(ROOT / "config.json"))
    ap.add_argument("--cases", default=str(ROOT / "cases"))
    ap.add_argument("--run-name", default=None, help="results/<run-name>/ (default: model+timestamp)")
    ap.add_argument("--model", default=None, help="override config model, e.g. zai/glm-5.3")
    ap.add_argument("--thinking", default=None, help="override thinking level (off|low|medium|high)")
    ap.add_argument("--tools", default=None, help="comma list of pi tools to enable; '' = none")
    ap.add_argument("--repeats", type=int, default=None)
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--filter", default="", help="only cases whose id contains this string")
    ap.add_argument("--limit", type=int, default=0, help="stop after N (case,repeat) pairs")
    ap.add_argument("--no-rerun-changed", action="store_true", help="do not re-evaluate cases whose code changed since they were recorded")
    ap.add_argument("--mock", action="store_true", help="do not call pi; fabricate verdicts to test the pipeline")
    ap.add_argument("--dry-run", action="store_true", help="print the pi command for the first case and exit")
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text())
    if args.tools is not None:
        args.tools = [t for t in args.tools.split(",") if t]
    repeats = args.repeats or cfg.get("repeats", 1)
    jobs = args.jobs or cfg.get("jobs", 1)
    model = args.model or cfg["model"]

    if not args.mock and not args.dry_run and not os.environ.get("ZAI_API_KEY") and model.startswith("zai/"):
        print("ZAI_API_KEY is not set: put it in bench/.env (ZAI_API_KEY=...) or export it", file=sys.stderr)
        return 1

    index = load_cases(Path(args.cases))

    run_name = args.run_name or (("mock_" if args.mock else "") + model.replace("/", "_") + time.strftime("_%Y%m%d_%H%M"))
    run_dir = ROOT / "results" / run_name
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    rec_path = run_dir / "records.jsonl"
    done = {}  # (case_id, repeat) -> code_sha of the recorded evaluation
    if rec_path.exists():
        for line in rec_path.read_text().splitlines():
            try:
                r = json.loads(line)
                done[(r["case_id"], r["repeat"])] = r.get("code_sha")
            except json.JSONDecodeError:
                pass
    (run_dir / "run_config.json").write_text(json.dumps({
        "config": cfg, "model": model, "thinking": args.thinking or cfg.get("thinking"),
        "tools": cfg.get("tools", []) if args.tools is None else args.tools, "repeats": repeats,
        "mock": args.mock, "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=2))

    user_tpl = (ROOT / "prompts" / "user.md").read_text()
    jobs_list = []
    for case in index:
        if args.filter and args.filter not in case["id"]:
            continue
        for rep in range(repeats):
            key = (case["id"], rep)
            if key in done and (done[key] == case.get("code_sha") or args.no_rerun_changed):
                continue  # already evaluated with this exact code
            jobs_list.append((case, rep))
    if args.limit:
        jobs_list = jobs_list[: args.limit]
    if args.dry_run:
        jobs_list = jobs_list[:1]
    print(f"[run] {run_name}: {len(jobs_list)} evaluations to do ({len(done)} already recorded), jobs={jobs}")

    t0 = time.time()
    n_done = 0
    with ThreadPoolExecutor(max_workers=jobs) as ex, rec_path.open("a") as fh:
        futs = {ex.submit(evaluate, c, r, cfg, args, user_tpl, raw_dir): (c, r) for c, r in jobs_list}
        for fut in as_completed(futs):
            case, rep = futs[fut]
            try:
                rec = fut.result()
            except Exception as e:  # noqa: BLE001
                rec = {"case_id": case["id"], "repeat": rep, "error": f"exception: {e}"}
            if rec.get("dry_run"):
                continue
            with LOCK:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                n_done += 1
                mark = "OK " if rec.get("pred_vulnerable") else "?? "
                print(f"[run] {mark}{n_done}/{len(jobs_list)} {case['id']} r{rep} -> {rec.get('pred_vulnerable')} {rec.get('pred_cwe') or ''} "
                      f"({rec.get('elapsed_sec', 0)}s){' ERR: ' + str(rec['error'])[:80] if rec.get('error') else ''}")
    print(f"[run] finished in {time.time() - t0:.0f}s -> {rec_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Ask one judge (pi + model + system prompt) whether a source file is vulnerable.

A judge is a dict: {"model": "zai/glm-5.3", "thinking": "medium", "prompt": "prompts/system.md", "tools": []}
"""
from __future__ import annotations

import json
import os
import random
import re
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USER_TPL = ROOT / "prompts" / "user.md"


def build_pi_cmd(judge: dict, prompt: str, pi_bin: str = "pi", extra_args: list[str] | None = None) -> list[str]:
    system_prompt = Path(judge.get("prompt", "prompts/system.md"))
    if not system_prompt.is_absolute():
        system_prompt = ROOT / system_prompt
    cmd = [
        pi_bin,
        "--mode", "json",
        "--no-session",
        "--no-extensions", "--no-skills", "--no-prompt-templates",
        "--no-context-files", "--no-mcp", "--no-approve",
        "--system-prompt", str(system_prompt),
        "--model", judge["model"],
    ]
    if judge.get("thinking"):
        cmd += ["--thinking", judge["thinking"]]
    tools = judge.get("tools") or []
    if not tools:
        cmd.append("--no-tools")
    else:
        cmd += ["--tools", ",".join(tools)]
    cmd += list(extra_args or [])
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
        if not isinstance(ev, dict):
            continue
        t = ev.get("type")
        if t == "message_end" and isinstance(ev.get("message"), dict) and ev["message"].get("role") == "assistant":
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
                if not isinstance(block, dict):
                    continue
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
    m = re.search(r'\bVULNERABLE"?\s*[:=]\s*"?(YES|NO|UNCERTAIN)\b', text, re.I)
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


def mock_verdict(seed: str, cwe: str, function: str) -> dict:
    """Deterministic fake answer for pipeline tests (no API call)."""
    rng = random.Random(seed)
    v = rng.choices(["YES", "NO", "UNCERTAIN"], weights=[0.7, 0.2, 0.1])[0]
    text = json.dumps({"vulnerable": v, "cwe": cwe if v == "YES" and rng.random() < 0.8 else None,
                       "function": function, "line": rng.randint(5, 30), "confidence": rng.randint(40, 99),
                       "reason": "mock"})
    return {"text": text, "thinking": "", "usage": {"input": 1000, "output": 80}, "tool_calls": 0, "error": None}


def render_prompt(code: str, language: str, source: str) -> str:
    """Fill metadata before code so placeholders in the source stay literal."""
    return USER_TPL.read_text().replace("{language}", language).replace("{source}", source).replace("{code}", code)


def run(code: str, judge: dict, *, language: str = "c", source: str = "code.c",
        timeout: int = 900, retries: int = 2, pi_bin: str = "pi",
        extra_args: list[str] | None = None, raw_path: Path | None = None) -> dict:
    """Judge one file.  Returns {"parsed": ..., "verdict": ..., "rc": ..., "stderr": ...}.

    pi runs in an empty temporary directory so that a judge with file tools enabled cannot
    read the case folder (its name and case.json contain the answer).
    """
    if retries < 0:
        raise ValueError("retries must be nonnegative")
    prompt = render_prompt(code, language, source)
    cmd = build_pi_cmd(judge, prompt, pi_bin, extra_args)
    parsed, rc, stderr = None, None, ""
    for attempt in range(retries + 1):
        stdout = ""
        execution_error = None
        execution_type = None
        with tempfile.TemporaryDirectory(prefix="bench-judge-") as cwd:
            try:
                r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=os.environ.copy())
                rc, stderr = r.returncode, r.stderr
                stdout = r.stdout
                if rc != 0:
                    execution_error = f"pi exited with status {rc}: {stderr.strip()[-300:]}"
                    execution_type = "process_exit"
            except subprocess.TimeoutExpired as e:
                rc, stderr = -1, "timeout"
                stdout = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                execution_error, execution_type = "timeout", "timeout"
            except OSError as e:
                rc, stderr = None, str(e)
                execution_error, execution_type = f"{type(e).__name__}: {e}", "execution"
        parsed = parse_json_stream(stdout)
        if raw_path:
            attempt_path = raw_path if attempt == 0 else raw_path.with_name(f"{raw_path.stem}.attempt{attempt + 1}{raw_path.suffix}")
            attempt_path.write_text(stdout)
        verdict = parse_verdict(parsed["text"])
        if execution_error:
            parsed.update(error=execution_error, error_type=execution_type)
        elif parsed["error"]:
            parsed["error_type"] = "response"
        elif verdict["vulnerable"] is None:
            parsed.update(error="could not parse a YES/NO/UNCERTAIN verdict", error_type="parse")
        else:
            parsed["error_type"] = None
        if not parsed["error"] or execution_type == "execution":
            break
        if attempt < retries:
            time.sleep(2 * (attempt + 1))
    return {"parsed": parsed, "verdict": parse_verdict("") if parsed["error"] else verdict, "rc": rc, "stderr": stderr}

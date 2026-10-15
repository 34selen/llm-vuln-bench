"""Ask one judge (pi + model + system prompt) whether a source file is vulnerable.

A judge is a dict: {"model": "zai/glm-5.3", "thinking": "medium", "prompt": "prompts/system.md"}.
Only a successful submit_verdict tool call is accepted as a prediction.
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
VERDICT_TOOL = "submit_verdict"
VERDICT_EXTENSION = Path(__file__).with_name("submit_verdict.ts")
VERDICT_SCHEMA = json.loads(Path(__file__).with_name("verdict.schema.json").read_text())


def effective_tools(requested: list[str] | None = None) -> list[str]:
    """Keep the evaluation tool set limited to verdict submission."""
    if requested is not None and requested != [VERDICT_TOOL]:
        raise ValueError("only the submit_verdict tool is allowed")
    return [VERDICT_TOOL]


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
        "--extension", str(VERDICT_EXTENSION),
        "--tools", ",".join(effective_tools(judge.get("tools"))),
        "--system-prompt", str(system_prompt),
        "--model", judge["model"],
    ]
    if judge.get("thinking"):
        cmd += ["--thinking", judge["thinking"]]
    selection_flags = {"--tools", "-t", "--no-tools", "-nt", "--exclude-tools", "-xt", "--extension", "-e"}
    if any(arg.split("=", 1)[0] in selection_flags for arg in (extra_args or [])):
        raise ValueError("pi_extra_args cannot override benchmark tools or extensions")
    cmd += list(extra_args or [])
    cmd += ["--", prompt]
    return cmd


def empty_verdict() -> dict:
    return {**dict.fromkeys(VERDICT_SCHEMA["properties"]), "parse": "none"}


def validate_verdict(value) -> dict:
    """Validate the flat tool schema without coercion or third-party dependencies."""
    properties = VERDICT_SCHEMA["properties"]
    if not isinstance(value, dict) or not set(VERDICT_SCHEMA["required"]) <= set(value) <= set(properties):
        raise ValueError("submit_verdict requires the schema's required fields and no unknown fields")
    for name, rule in properties.items():
        if name not in value:  # optional field omitted: not applicable
            continue
        item = value[name]
        allowed = rule["type"] if isinstance(rule["type"], list) else [rule["type"]]
        integer = type(item) is int or (type(item) is float and item.is_integer())
        kind = "null" if item is None else "string" if isinstance(item, str) else "integer" if integer else "invalid"
        if kind not in allowed:
            raise ValueError(f"invalid type for submit_verdict.{name}")
        if "enum" in rule and item not in rule["enum"]:
            raise ValueError(f"invalid submit_verdict.{name}: {item!r}")
        if isinstance(item, str):
            if len(item) < rule.get("minLength", 0) or ("pattern" in rule and not re.fullmatch(rule["pattern"], item)):
                raise ValueError(f"invalid submit_verdict.{name}")
        elif item < rule.get("minimum", item) or item > rule.get("maximum", item):
            raise ValueError(f"out-of-range submit_verdict.{name}")
    value = {**dict.fromkeys(properties), **value}
    return {**value, **{k: int(value[k]) for k in ("line", "confidence") if value[k] is not None}, "parse": "tool"}


def sum_usage(usages: list[dict | None]) -> dict | None:
    """Add token counts and the provider-reported cost of several model calls."""
    usages = [u for u in usages if u]
    if not usages:
        return None
    usage = {}
    for u in usages:
        for key, value in u.items():
            if isinstance(value, (int, float)):
                usage[key] = usage.get(key, 0) + value
            elif key == "cost" and isinstance(value, dict):
                cost = usage.setdefault("cost", {})
                for k, v in value.items():
                    if isinstance(v, (int, float)):
                        cost[k] = cost.get(k, 0) + v
    return usage


def parse_json_stream(stdout: str) -> dict:
    """Correlate executed tool calls; assistant text is kept only as a log."""
    text_parts, thinking_parts, usages = [], [], []
    starts, submissions = {}, []
    error = None
    verdict_error = None
    invalid_error = None
    tool_calls = invalid_calls = 0
    for line in stdout.split("\n"):
        try:
            ev = json.loads(line.strip("\r"))
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict):
            continue
        t = ev.get("type")
        msg = ev.get("message")
        if t == "message_end" and isinstance(msg, dict) and msg.get("role") == "assistant":
            content = msg.get("content", [])
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
            if isinstance(msg.get("usage"), dict):
                usages.append(msg["usage"])
            if msg.get("stopReason") == "error":
                error = msg.get("errorMessage") or "stopReason=error"
        elif t == "tool_execution_start":
            tool_calls += 1
            call_id = ev.get("toolCallId")
            if ev.get("toolName") != VERDICT_TOOL or not call_id or call_id in starts:
                verdict_error = "unexpected or duplicate tool call"
            else:
                starts[call_id] = ev.get("args")
        elif t == "tool_execution_end":
            call_id = ev.get("toolCallId")
            if ev.get("toolName") != VERDICT_TOOL or call_id not in starts:
                verdict_error = "unmatched submit_verdict result"
                continue
            args = starts.pop(call_id)
            result = ev.get("result")
            if ev.get("isError") is not False or not isinstance(result, dict) or result.get("isError"):
                content = result.get("content", []) if isinstance(result, dict) else []
                detail = " ".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
                invalid_calls += 1
                invalid_error = "submit_verdict execution failed: " + detail[:300]
                if submissions:  # a call after a recorded verdict is a duplicate submission
                    verdict_error = invalid_error
                # Otherwise the model saw the error and may resubmit; only the final outcome matters.
                continue
            try:
                verdict = validate_verdict(args)
                details = result.get("details")
                if not isinstance(details, dict) or details.get("verdict") != args:
                    raise ValueError("submit_verdict result does not match its arguments")
                submissions.append(verdict)
            except ValueError as e:
                verdict_error = str(e)
        elif t == "error" or (t == "message_update" and isinstance(ev.get("assistantMessageEvent"), dict) and ev["assistantMessageEvent"].get("type") == "error"):
            error = json.dumps(ev)[:500]
    if starts:
        verdict_error = "submit_verdict did not finish"
    if len(submissions) != 1:
        verdict_error = verdict_error or invalid_error or "expected exactly one successful submit_verdict call"
    usage = sum_usage(usages)
    return {
        "text": "\n".join(text_parts).strip(), "thinking": "\n".join(thinking_parts).strip(),
        "usage": usage, "tool_calls": tool_calls, "invalid_tool_calls": invalid_calls, "error": error,
        "verdict": submissions[0] if not verdict_error else empty_verdict(),
        "verdict_error": verdict_error,
    }


def mock_verdict(seed: str, cwe: str, function: str) -> dict:
    """Deterministic fake answer for pipeline tests (no API call)."""
    rng = random.Random(seed)
    v = rng.choices(["YES", "NO", "UNCERTAIN"], weights=[0.7, 0.2, 0.1])[0]
    verdict = {"vulnerable": v, "function": function, "line": rng.randint(5, 30),
               "confidence": rng.randint(40, 99), "reason": "mock"}
    if v == "YES" and rng.random() < 0.8:
        verdict["cwe"] = cwe
    events = [
        {"type": "message_end", "message": {"role": "assistant", "content": [], "usage": {"input": 1000, "output": 80}}},
        {"type": "tool_execution_start", "toolName": VERDICT_TOOL, "toolCallId": "mock", "args": verdict},
        {"type": "tool_execution_end", "toolName": VERDICT_TOOL, "toolCallId": "mock", "isError": False, "result": {"details": {"verdict": verdict}}},
    ]
    return parse_json_stream("\n".join(json.dumps(e) for e in events))


def render_prompt(code: str, source: str) -> str:
    """Fill metadata before code so placeholders in the source stay literal."""
    return USER_TPL.read_text().replace("{source}", source).replace("{code}", code)


def run(code: str, judge: dict, *, source: str = "code.c",
        timeout: int = 900, retries: int = 2, pi_bin: str = "pi",
        extra_args: list[str] | None = None, raw_path: Path | None = None) -> dict:
    """Judge one file.  Returns {"parsed": ..., "verdict": ..., "rc": ..., "stderr": ...}.

    pi runs in an empty temporary directory so that a judge with file tools enabled cannot
    read the case folder (its name and case.json contain the answer).
    """
    if retries < 0:
        raise ValueError("retries must be nonnegative")
    prompt = render_prompt(code, source)
    cmd = build_pi_cmd(judge, prompt, pi_bin, extra_args)
    parsed, rc, stderr = None, None, ""
    attempt_usages = []
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
        # Failed attempts are billed too, so usage covers every attempt of this evaluation.
        attempt_usages.append(parsed["usage"])
        parsed.update(usage=sum_usage(attempt_usages), attempts=attempt + 1)
        if raw_path:
            attempt_path = raw_path if attempt == 0 else raw_path.with_name(f"{raw_path.stem}.attempt{attempt + 1}{raw_path.suffix}")
            attempt_path.write_text(stdout)
        verdict = parsed["verdict"]
        if execution_error:
            parsed.update(error=execution_error, error_type=execution_type)
        elif parsed["verdict_error"] and parsed["tool_calls"]:
            parsed.update(error=parsed["verdict_error"], error_type="parse")
        elif parsed["error"]:
            parsed["error_type"] = "response"
        elif verdict["vulnerable"] is None:
            parsed.update(error=parsed["verdict_error"], error_type="parse")
        else:
            parsed["error_type"] = None
        if not parsed["error"] or execution_type == "execution":
            break
        if attempt < retries:
            time.sleep(2 * (attempt + 1))
    return {"parsed": parsed, "verdict": empty_verdict() if parsed["error"] else verdict, "rc": rc, "stderr": stderr}

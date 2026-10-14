"""Regression checks using temporary cases and fake pi responses; no API calls."""
import contextlib
import csv
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import aggregate
import run_pi
from benchcore import judge


def stream(text, **message_fields):
    message = {"role": "assistant", "content": [{"type": "text", "text": text}], **message_fields}
    return json.dumps({"type": "message_end", "message": message}) + "\n"


def verdict(**changes):
    return {"vulnerable": "YES", "cwe": "CWE-121", "function": "entry", "line": 1,
            "confidence": 90, "reason": "fixture", **changes}


def tool_stream(arguments=None, *, is_error=False, name="submit_verdict", call_id="call_1"):
    arguments = verdict() if arguments is None else arguments
    events = [
        {"type": "message_end", "message": {"role": "assistant", "content": [
            {"type": "toolCall", "id": call_id, "name": name, "arguments": arguments}],
            "usage": {"input": 100, "output": 20}}},
        {"type": "tool_execution_start", "toolCallId": call_id, "toolName": name, "args": arguments},
        {"type": "tool_execution_end", "toolCallId": call_id, "toolName": name,
         "isError": is_error, "result": {"details": {"verdict": arguments}}},
    ]
    return "\n".join(json.dumps(e) for e in events) + "\n"


class JudgeTests(unittest.TestCase):
    def test_prompt_preserves_code_placeholders(self):
        code = 'print("{language} {source} {code}")'
        prompt = judge.render_prompt(code, "src/main.py")
        self.assertEqual(prompt, f"Check whether this code is vulnerable.\n\nSource file: src/main.py\n\n```\n{code}\n```\n")

    def test_failures_are_explicit_and_have_no_prediction(self):
        valid = tool_stream()
        cases = [
            (subprocess.CompletedProcess([], 0, stream("hello"), ""), "parse"),
            (subprocess.CompletedProcess([], 0, "", ""), "parse"),
            (subprocess.CompletedProcess([], 0, stream('{"vulnerable":"MAYBE"}'), ""), "parse"),
            (subprocess.CompletedProcess([], 0, stream("VULNERABLE: NOPE"), ""), "parse"),
            (subprocess.CompletedProcess([], 0, '42\n"noise"\n[]\n', ""), "parse"),
            (subprocess.CompletedProcess([], 0, stream('{"vulnerable":"YES"}'), ""), "parse"),
            (subprocess.CompletedProcess([], 1, valid, "failure"), "process_exit"),
            (subprocess.TimeoutExpired([], 1, output=valid.encode()), "timeout"),
            (FileNotFoundError("missing pi"), "execution"),
            (subprocess.CompletedProcess([], 0, stream("", stopReason="error", errorMessage="provider error"), ""), "response"),
        ]
        for result, error_type in cases:
            with self.subTest(error_type=error_type, result=type(result).__name__):
                fake = {"side_effect": result} if isinstance(result, Exception) else {"return_value": result}
                with patch.object(judge.subprocess, "run", **fake):
                    out = judge.run("source", {"model": "fake"}, retries=0)
                self.assertEqual(out["parsed"]["error_type"], error_type)
                self.assertTrue(out["parsed"]["error"])
                self.assertIsNone(out["verdict"]["vulnerable"])

    def test_parse_failure_retries_and_preserves_each_raw_response(self):
        bad = stream("not a verdict")
        good = tool_stream(verdict(vulnerable="NO"))
        responses = [subprocess.CompletedProcess([], 0, s, "") for s in (bad, good)]
        with tempfile.TemporaryDirectory() as td:
            raw = Path(td) / "response.jsonl"
            with patch.object(judge.subprocess, "run", side_effect=responses) as call, patch.object(judge.time, "sleep"):
                out = judge.run("source", {"model": "fake"}, retries=1, raw_path=raw)
            self.assertEqual(call.call_count, 2)
            self.assertIsNone(out["parsed"]["error"])
            self.assertEqual(out["verdict"]["vulnerable"], "NO")
            self.assertEqual(raw.read_text(), bad)
            self.assertEqual(raw.with_name("response.attempt2.jsonl").read_text(), good)

    def test_uncertain_is_a_valid_prediction(self):
        response = subprocess.CompletedProcess([], 0, tool_stream(verdict(vulnerable="UNCERTAIN", cwe=None, function=None, line=None)), "")
        with patch.object(judge.subprocess, "run", return_value=response):
            out = judge.run("source", {"model": "fake"}, retries=0)
        self.assertIsNone(out["parsed"]["error"])
        self.assertEqual(out["verdict"]["vulnerable"], "UNCERTAIN")

    def test_invalid_verdict_values_retry_until_valid_tool_call(self):
        for arguments in [verdict(vulnerable="NO IDEA"), verdict(vulnerable="MAYBE", reason="VULNERABLE: YES")]:
            with self.subTest(arguments=arguments):
                bad = subprocess.CompletedProcess([], 0, tool_stream(arguments), "")
                good = subprocess.CompletedProcess([], 0, tool_stream(verdict(vulnerable="NO")), "")
                with patch.object(judge.subprocess, "run", side_effect=[bad, good]) as call, patch.object(judge.time, "sleep"):
                    out = judge.run("source", {"model": "fake"}, retries=2)
                self.assertEqual(call.call_count, 2)
                self.assertIsNone(out["parsed"]["error"])
                self.assertEqual(out["verdict"]["vulnerable"], "NO")
                self.assertEqual(out["verdict"]["parse"], "tool")

    def test_invalid_verdict_after_all_retries_remains_an_error(self):
        bad = subprocess.CompletedProcess([], 0, tool_stream(verdict(vulnerable="MAYBE", reason="VULNERABLE: YES")), "")
        with patch.object(judge.subprocess, "run", return_value=bad) as call, patch.object(judge.time, "sleep"):
            out = judge.run("source", {"model": "fake"}, retries=2)
        self.assertEqual(call.call_count, 3)
        self.assertEqual(out["parsed"]["error_type"], "parse")
        self.assertTrue(out["parsed"]["error"])
        self.assertIsNone(out["verdict"]["vulnerable"])

    def test_tool_arguments_are_strictly_validated(self):
        missing = verdict()
        del missing["reason"]
        invalid = [missing, verdict(extra="field"), verdict(confidence=101), verdict(confidence=-1),
                   verdict(confidence=True), verdict(confidence="90"), verdict(line=0),
                   verdict(line=True), verdict(cwe="121"), verdict(reason=""), verdict(function=42)]
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                parsed = judge.parse_json_stream(tool_stream(arguments))
                self.assertIsNone(parsed["verdict"]["vulnerable"])
                self.assertTrue(parsed["verdict_error"])

    def test_successful_tool_call_is_used_instead_of_final_text(self):
        parsed = judge.parse_json_stream(tool_stream() + stream('{"vulnerable":"NO"}'))
        self.assertEqual(parsed["verdict"]["vulnerable"], "YES")
        self.assertEqual(parsed["verdict"]["parse"], "tool")
        self.assertIn('"NO"', parsed["text"])

    def test_failed_unfinished_multiple_and_unknown_calls_are_rejected(self):
        complete = tool_stream()
        unfinished = "\n".join(complete.splitlines()[:-1])
        unmatched = complete.splitlines()[-1]
        mismatch = json.loads(complete.splitlines()[-1])
        mismatch["result"]["details"]["verdict"]["vulnerable"] = "NO"
        mismatched = "\n".join(complete.splitlines()[:-1] + [json.dumps(mismatch)])
        for data in [tool_stream(is_error=True), unfinished, unmatched, mismatched,
                     complete + tool_stream(call_id="call_2"), tool_stream(name="bash")]:
            with self.subTest(data=data):
                parsed = judge.parse_json_stream(data)
                self.assertIsNone(parsed["verdict"]["vulnerable"])
                self.assertTrue(parsed["verdict_error"])

    def test_command_enables_only_the_explicit_verdict_extension(self):
        cmd = judge.build_pi_cmd({"model": "fake"}, "prompt")
        self.assertEqual(cmd[cmd.index("--tools") + 1], "submit_verdict")
        self.assertEqual(cmd[cmd.index("--extension") + 1], str(judge.VERDICT_EXTENSION))
        self.assertIn("--no-extensions", cmd)
        self.assertIn("--no-mcp", cmd)
        self.assertNotIn("--no-tools", cmd)
        with self.assertRaises(ValueError):
            judge.build_pi_cmd({"model": "fake", "tools": ["bash"]}, "prompt")
        with self.assertRaises(ValueError):
            judge.build_pi_cmd({"model": "fake"}, "prompt", extra_args=["--tools", "bash"])


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "cases").mkdir()
        shutil.copytree(run_pi.ROOT / "prompts", self.root / "prompts")
        cfg = {"model": "test-model", "thinking": "medium", "tools": ["submit_verdict"], "repeats": 2, "jobs": 2, "retries": 0}
        (self.root / "config.json").write_text(json.dumps(cfg))
        self.samples = {
            name: {"cwe": "CWE-121", "title": "fixture", "function": "entry", "language": language}
            for name, language in [("c_sample", "c"), ("cpp_sample", "cpp"), ("py_sample", "python"), ("sol_sample", "solidity")]
        }
        self.write_samples()
        self.addCleanup(patch.stopall)
        patch.object(run_pi, "ROOT", self.root).start()
        patch.object(aggregate, "ROOT", self.root).start()

    def write_samples(self):
        (self.root / "samples.json").write_text(json.dumps(self.samples))

    def add_case(self, sample="c_sample", source="code.c", metadata=None, label="vuln"):
        case = self.root / "cases" / f"{sample}__{label}__original"
        (case / source).parent.mkdir(parents=True, exist_ok=True)
        (case / source).write_text("fixture source\n")
        if metadata is not None:
            (case / "case.json").write_text(json.dumps(metadata))
        return case

    def run_cli(self, *args):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["run_pi.py", *args]), contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = run_pi.main()
        return result, output.getvalue(), errors.getvalue()

    def aggregate_cli(self, name):
        with patch.object(sys, "argv", ["aggregate.py", name]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(aggregate.main(), 0)
        with (self.root / "results" / name / "summary.csv").open() as fh:
            return list(csv.DictReader(fh))

    def records(self, name):
        return [json.loads(line) for line in (self.root / "results" / name / "records.jsonl").read_text().splitlines()]

    def test_multiple_languages_recorded_and_aggregated_separately(self):
        for sample, source in [("c_sample", "code.c"), ("cpp_sample", "code.cpp"), ("py_sample", "code.py"), ("sol_sample", "code.sol")]:
            self.add_case(sample, source)
        self.assertEqual(self.run_cli("--mock", "--run-name", "languages")[0], 0)
        records = self.records("languages")
        self.assertEqual(len(records), 8)
        self.assertEqual({r["language"] for r in records}, {"c", "cpp", "python", "solidity"})
        self.assertEqual({r["source"] for r in records}, {"code.c", "code.cpp", "code.py", "code.sol"})
        self.assertTrue(all(r["response_mode"] == "tool" and r["pred_parse"] == "tool" and r["tool_calls"] == 1 for r in records))
        self.assertTrue(all(set(r["tool_arguments"]) == set(judge.VERDICT_SCHEMA["required"]) for r in records))
        cfg = json.loads((self.root / "results/languages/run_config.json").read_text())
        self.assertEqual((cfg["response_mode"], cfg["tools"]), ("tool", ["submit_verdict"]))
        rows = self.aggregate_cli("languages")
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r["n"] == "2" and r["errors"] == "0" for r in rows))

    def test_explicit_source_and_case_language_override(self):
        self.add_case("c_sample", "src/main.py", {"source": "src/main.py", "language": "python"})
        loaded = run_pi.load_cases(self.root / "cases")
        self.assertEqual((loaded[0]["source"], loaded[0]["language"]), ("src/main.py", "python"))

    def test_source_from_sample_without_manifest(self):
        self.samples["py_sample"]["source"] = "src/main.py"
        self.write_samples()
        self.add_case("py_sample", "src/main.py")
        loaded = run_pi.load_cases(self.root / "cases")
        self.assertEqual(loaded[0]["source"], "src/main.py")

    def test_ambiguous_and_escaping_source_rejected(self):
        case = self.add_case()
        (case / "code.py").write_text("fixture\n")
        with self.assertRaisesRegex(ValueError, "expected one code"):
            run_pi.load_cases(self.root / "cases")
        (case / "case.json").write_text(json.dumps({"source": "../../config.json"}))
        with self.assertRaisesRegex(ValueError, "inside the case directory"):
            run_pi.load_cases(self.root / "cases")

    def test_invalid_label_rejected(self):
        self.add_case(label="typo")
        with self.assertRaisesRegex(ValueError, "label must"):
            run_pi.load_cases(self.root / "cases")

    def test_duplicate_run_does_not_change_any_files(self):
        self.add_case()
        self.assertEqual(self.run_cli("--mock", "--run-name", "once")[0], 0)
        directory = self.root / "results" / "once"
        snapshot = {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
        result, _, error = self.run_cli("--mock", "--run-name", "once", "--model", "changed", "--prompt", str(self.root / "prompts/system_any.md"))
        self.assertEqual(result, 1)
        self.assertIn("run already exists", error)
        self.assertEqual(snapshot, {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()})

    def test_empty_existing_run_is_also_rejected(self):
        self.add_case()
        (self.root / "results" / "reserved").mkdir(parents=True)
        self.assertEqual(self.run_cli("--mock", "--run-name", "reserved")[0], 1)
        self.assertEqual(list((self.root / "results/reserved").iterdir()), [])

    def test_invalid_run_path_rejected(self):
        for name in ("../escape", "/tmp/escape", ".", ".."):
            with self.subTest(name=name), self.assertRaises(SystemExit) as error:
                self.run_cli("--mock", "--run-name", name)
            self.assertEqual(error.exception.code, 2)

    def test_dry_run_creates_no_files_and_empty_selection_fails(self):
        self.assertEqual(self.run_cli("--mock", "--run-name", "empty")[0], 1)
        self.add_case()
        self.assertEqual(self.run_cli("--dry-run", "--run-name", "preview")[0], 0)
        self.assertFalse((self.root / "results").exists())

    def test_call_exception_keeps_metadata_and_counts_in_summary(self):
        self.add_case("py_sample", "src/main.py", {"source": "src/main.py"})
        with patch.object(judge, "run", side_effect=RuntimeError("fixture failure")):
            self.assertEqual(self.run_cli("--run-name", "failure")[0], 0)
        records = self.records("failure")
        for r in records:
            self.assertEqual(r["error_type"], "exception")
            self.assertEqual((r["language"], r["source"], r["cwe"]), ("python", "src/main.py", "CWE-121"))
            self.assertEqual(r["model"], "test-model")
            self.assertTrue(r["expected_vulnerable"])
            self.assertIsNone(r["pred_vulnerable"])
            self.assertIn("finished", r)
        row = self.aggregate_cli("failure")[0]
        self.assertEqual((row["n"], row["errors"], row["unparsed"], row["yes"], row["no"]), ("2", "2", "2", "0", "0"))
        self.assertIn("## Errors (2)", (self.root / "results/failure/summary.md").read_text())

    def test_nonzero_exit_with_valid_json_is_not_a_successful_prediction(self):
        self.add_case()
        response = subprocess.CompletedProcess([], 1, tool_stream(), "fixture error")
        with patch.object(judge.subprocess, "run", return_value=response):
            self.assertEqual(self.run_cli("--run-name", "nonzero")[0], 0)
        self.assertTrue(all(r["error_type"] == "process_exit" for r in self.records("nonzero")))
        row = self.aggregate_cli("nonzero")[0]
        self.assertEqual((row["yes"], row["errors"]), ("0", "2"))

    def test_legacy_exception_records_are_not_dropped(self):
        directory = self.root / "results/legacy"
        directory.mkdir(parents=True)
        record = {"case_id": "c_sample__safe__original", "repeat": 0, "error": "legacy failure"}
        (directory / "records.jsonl").write_text(json.dumps(record) + "\n")
        row = self.aggregate_cli("legacy")[0]
        self.assertEqual((row["language"], row["label"], row["n"], row["errors"]), ("c", "safe", "1", "1"))


if __name__ == "__main__":
    unittest.main()

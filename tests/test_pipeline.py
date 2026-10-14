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


class JudgeTests(unittest.TestCase):
    def test_language_and_source_in_prompt_preserve_code_placeholders(self):
        code = 'print("{language} {source} {code}")'
        prompt = judge.render_prompt(code, "python", "src/main.py")
        self.assertIn("Language: python", prompt)
        self.assertIn("Source file: src/main.py", prompt)
        self.assertIn("```python\n" + code, prompt)
        self.assertNotIn("C source file", prompt)

    def test_failures_are_explicit_and_have_no_prediction(self):
        valid = stream('{"vulnerable":"YES","cwe":"CWE-121"}')
        cases = [
            (subprocess.CompletedProcess([], 0, stream("hello"), ""), "parse"),
            (subprocess.CompletedProcess([], 0, "", ""), "parse"),
            (subprocess.CompletedProcess([], 0, stream('{"vulnerable":"MAYBE"}'), ""), "parse"),
            (subprocess.CompletedProcess([], 0, stream("VULNERABLE: NOPE"), ""), "parse"),
            (subprocess.CompletedProcess([], 0, '42\n"noise"\n[]\n', ""), "parse"),
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
        good = stream('{"vulnerable":"NO"}')
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
        response = subprocess.CompletedProcess([], 0, stream('{"vulnerable":"UNCERTAIN"}'), "")
        with patch.object(judge.subprocess, "run", return_value=response):
            out = judge.run("source", {"model": "fake"}, retries=0)
        self.assertIsNone(out["parsed"]["error"])
        self.assertEqual(out["verdict"]["vulnerable"], "UNCERTAIN")


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "cases").mkdir()
        shutil.copytree(run_pi.ROOT / "prompts", self.root / "prompts")
        cfg = {"model": "test-model", "thinking": "medium", "tools": [], "repeats": 2, "jobs": 2, "retries": 0}
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
        response = subprocess.CompletedProcess([], 1, stream('{"vulnerable":"YES"}'), "fixture error")
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

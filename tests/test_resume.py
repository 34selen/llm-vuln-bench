"""--resume continues a run where it stopped, without changing the cell.

A long run that dies partway used to be unrecoverable: the run name was
rejected on the way back in, so the only option was a fresh name, which
re-pays for every evaluation already recorded.  These tests pin the two
decisions that keep resuming honest -- an already-recorded pair is never
evaluated twice (not even when it errored), and a resume into changed
measurement settings is refused rather than silently mixed.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import run_pi

CODE = "int main(void) { return 0; }\n"
CASES = ("cwe121_sbo__vuln__alpha", "cwe121_sbo__safe__beta")


class ResumeTest(unittest.TestCase):
    def setUp(self):
        self.cases_dir = Path(tempfile.mkdtemp(prefix="bench-resume-cases-"))
        self.addCleanup(shutil.rmtree, self.cases_dir, True)
        for name in CASES:
            case = self.cases_dir / name
            case.mkdir()
            (case / "code.c").write_text(CODE)
        self.run_name = "test_resume_" + uuid4().hex[:8]
        self.run_dir = run_pi.ROOT / "results" / self.run_name
        self.addCleanup(shutil.rmtree, self.run_dir, True)
        # 2 cases x repeats 2
        self.all_pairs = {(name, rep) for name in CASES for rep in (0, 1)}

    def run_main(self, *extra, run_name=None):
        argv = ["run_pi.py", "--mock", "--repeats", "2", "--jobs", "1",
                "--cases", str(self.cases_dir),
                "--run-name", run_name or self.run_name, *extra]
        with patch.object(sys, "argv", argv):
            return run_pi.main()

    def records(self):
        lines = (self.run_dir / "records.jsonl").read_text().splitlines()
        out = []
        for line in lines:
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out

    def pairs(self):
        return [(r["case_id"], r["repeat"]) for r in self.records()]

    # --- the main path -----------------------------------------------------

    def test_resume_evaluates_only_the_missing_pairs(self):
        self.assertEqual(self.run_main("--limit", "2"), 0)
        first = self.pairs()
        self.assertEqual(len(first), 2)

        self.assertEqual(self.run_main("--resume"), 0)
        after = self.pairs()
        self.assertEqual(len(after), 4, "resume must not re-evaluate recorded pairs")
        self.assertEqual(set(after), self.all_pairs)
        self.assertEqual(len(set(after)), len(after), "no pair may appear twice")
        self.assertEqual(after[:2], first, "earlier records are appended to, not rewritten")

    def test_resume_on_a_finished_run_does_nothing(self):
        self.assertEqual(self.run_main(), 0)
        before = self.pairs()
        self.assertEqual(len(before), 4)
        self.assertEqual(self.run_main("--resume"), 0)
        self.assertEqual(self.pairs(), before)

    def test_resume_is_recorded_in_run_config(self):
        self.run_main("--limit", "1")
        self.run_main("--resume")
        cfg = json.loads((self.run_dir / "run_config.json").read_text())
        self.assertEqual(len(cfg.get("resumed", [])), 1)

    def test_limit_with_resume_counts_further_pairs(self):
        self.run_main("--limit", "1")
        self.assertEqual(self.run_main("--resume", "--limit", "1"), 0)
        self.assertEqual(len(self.pairs()), 2)

    # --- the pairs that must not be re-run ---------------------------------

    def test_an_errored_pair_is_not_re_evaluated(self):
        self.run_main("--limit", "1")
        done = self.pairs()[0]
        errored = sorted(self.all_pairs - {done})[0]
        with (self.run_dir / "records.jsonl").open("a") as fh:
            fh.write(json.dumps({"case_id": errored[0], "repeat": errored[1],
                                 "error": "timeout", "error_type": "timeout",
                                 "pred_vulnerable": None}) + "\n")

        self.assertEqual(self.run_main("--resume"), 0)
        pairs = self.pairs()
        self.assertEqual(len(pairs), 4)
        self.assertEqual(pairs.count(errored), 1,
                         "an errored pair must not get a retry the original run never had")
        still_errored = [r for r in self.records()
                         if (r["case_id"], r["repeat"]) == errored]
        self.assertEqual(still_errored[0]["error"], "timeout")

    def test_a_torn_last_line_lets_that_pair_run_again(self):
        self.run_main("--limit", "1")
        with (self.run_dir / "records.jsonl").open("a") as fh:
            fh.write('{"case_id": "cwe121_sbo__vuln__alp')

        self.assertEqual(self.run_main("--resume"), 0)
        self.assertEqual(set(self.pairs()), self.all_pairs)
        for n, line in enumerate((self.run_dir / "records.jsonl").read_text().splitlines(), 1):
            json.loads(line)   # the fragment must be gone, not fused onto a record

    def test_a_torn_tail_does_not_block_a_later_resume(self):
        self.run_main("--limit", "1")
        with (self.run_dir / "records.jsonl").open("a") as fh:
            fh.write('{"case_id": "cwe121_sbo__vuln__alp')
        self.assertEqual(self.run_main("--resume", "--limit", "1"), 0)
        self.assertEqual(self.run_main("--resume"), 0, "one crash must not block resuming forever")
        self.assertEqual(set(self.pairs()), self.all_pairs)

    def test_a_torn_line_in_the_middle_refuses_to_resume(self):
        self.run_main("--limit", "2")
        text = (self.run_dir / "records.jsonl").read_text()
        (self.run_dir / "records.jsonl").write_text("{not json\n" + text)
        self.assertEqual(self.run_main("--resume"), 1,
                         "a damaged file in the middle is not a torn tail")

    # --- refusals ----------------------------------------------------------

    def test_resume_refuses_when_the_measurement_changed(self):
        self.run_main("--limit", "2")
        before = self.pairs()
        self.assertEqual(self.run_main("--resume", "--thinking", "high"), 1)
        self.assertEqual(self.pairs(), before, "a refused resume writes nothing")

    def test_resume_refuses_a_different_repeat_count(self):
        self.run_main("--limit", "2")
        argv = ["run_pi.py", "--mock", "--repeats", "3", "--jobs", "1",
                "--cases", str(self.cases_dir), "--run-name", self.run_name, "--resume"]
        with patch.object(sys, "argv", argv):
            self.assertEqual(run_pi.main(), 1)

    def test_resume_without_an_existing_run_fails(self):
        self.assertEqual(self.run_main("--resume", run_name="test_resume_" + uuid4().hex[:8]), 1)

    def test_resume_needs_a_run_name(self):
        argv = ["run_pi.py", "--mock", "--cases", str(self.cases_dir), "--resume"]
        with patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
            run_pi.main()

    def test_a_second_run_without_resume_is_still_rejected(self):
        self.run_main("--limit", "1")
        before = self.pairs()
        self.assertEqual(self.run_main(), 1, "an existing run name without --resume is rejected")
        self.assertEqual(self.pairs(), before)


if __name__ == "__main__":
    unittest.main()

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import aggregate
import logic_benchmark
import logic_calibration


class LogicBenchmarkTests(unittest.TestCase):
    def test_default_suite_checks_labels_and_records_distinct_work(self):
        cases = logic_benchmark.load_suite(logic_benchmark.DEFAULT_SUITE)
        rows = {case[0]: logic_benchmark.profile(*case) for case in cases}
        self.assertEqual(len(rows), 12)
        self.assertEqual(rows["choice-unsat"]["answer"], "UNSAT")
        self.assertGreater(rows["choice-unsat"]["search_nodes"], rows["unit-unsat"]["search_nodes"])
        self.assertLess(rows["choice-sat-with-unit"]["search_nodes"], rows["choice-sat"]["search_nodes"])
        self.assertEqual(rows["independent-sat"]["block_count"], 2)
        self.assertEqual(rows["independent-sat"]["clause_density"], 1)

    def test_wrong_label_and_shared_variables_fail(self):
        with self.assertRaisesRegex(ValueError, "reference solver found UNSAT"):
            logic_benchmark.profile("conflict", "SAT", (((1,), (-1,)),))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite.json"
            path.write_text(json.dumps([
                {"case_id": "shared", "expected": "SAT", "blocks": [[[1]], [[-1]]]},
            ]))
            with self.assertRaisesRegex(ValueError, "disjoint variables"):
                logic_benchmark.load_suite(path)

    def test_cli_exports_questions_without_answers_and_scores_missing_separately(self):
        command = [sys.executable, str(Path(logic_benchmark.__file__).resolve())]
        questions = json.loads(subprocess.check_output([*command, "--questions"], text=True))
        self.assertTrue(all(set(question) == {"case_id", "blocks"} for question in questions))
        with tempfile.TemporaryDirectory() as directory:
            predictions = Path(directory) / "answers.json"
            predictions.write_text(json.dumps({
                "unit-sat": "SAT",
                "unit-unsat": "SAT",
                "choice-sat": "UNCERTAIN",
            }))
            report = json.loads(subprocess.check_output(
                [*command, "--predictions", str(predictions)], text=True,
            ))
        self.assertEqual(report["score"], {
            "cases": 12, "correct": 1, "incorrect": 1, "uncertain": 1, "missing": 9,
        })


class CalibrationTests(unittest.TestCase):
    def test_calibration_checks_all_labels_and_controls(self):
        report = logic_calibration.calibrate(
            logic_benchmark.DEFAULT_SUITE, logic_calibration.DEFAULT_PLAN,
        )
        self.assertEqual(report["verified_cases"], 12)
        self.assertEqual(len(report["comparisons"]), 6)
        self.assertEqual(set(report["comparisons"][-1]["axes"]), set(logic_calibration.AXIS_NAMES))

    def test_mislabeled_axis_fails_even_when_both_labels_are_sat(self):
        profiles = {
            case[0]: logic_benchmark.profile(*case)
            for case in logic_benchmark.load_suite(logic_benchmark.DEFAULT_SUITE)
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text(json.dumps([
                {"before": "choice-sat", "after": "choice-sat-with-unit", "axes": ["block_count"]},
            ]))
            with self.assertRaisesRegex(ValueError, "changed clause_count"):
                logic_calibration.evaluate_comparisons(path, profiles)


class ReviewOutcomeTests(unittest.TestCase):
    def test_error_and_abstention_do_not_count_as_misses(self):
        records = [
            {"label": label, "pred_vulnerable": verdict}
            for label, verdict in (
                ("vuln", "YES"), ("vuln", "NO"), ("vuln", "UNCERTAIN"), ("vuln", None),
                ("safe", "YES"), ("safe", "NO"),
            )
        ]
        report = aggregate.review_outcomes(records)
        self.assertIn("| vuln (FN) | 4 | 2 | 1/2 | 1/4 | 1 | 1 |", report)
        self.assertIn("| safe (FP) | 2 | 2 | 1/2 | 1/2 | 0 | 0 |", report)

    def test_all_errors_leave_the_decisive_denominator_unavailable(self):
        report = aggregate.review_outcomes([{"label": "vuln", "pred_vulnerable": None}])
        self.assertIn("| vuln (FN) | 1 | 0 | - | 0/1 | 0 | 1 |", report)

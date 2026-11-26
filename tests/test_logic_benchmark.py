import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import aggregate
import logic_benchmark
import logic_calibration


EVALUATION_SUITE = logic_benchmark.DEFAULT_SUITE.with_name("logic-evaluation.json")
CLI = [sys.executable, str(Path(logic_benchmark.__file__).resolve())]


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
        self.assertEqual(report["metrics"]["accuracy_decisive"], {"count": 1, "total": 2, "rate": 0.5})
        self.assertEqual(report["metrics"]["accuracy_all"]["total"], 12)
        self.assertEqual(report["metrics"]["coverage_decisive"]["count"], 2)

    def test_public_forms_blind_metadata_and_bind_scoring_to_the_suite_and_seed(self):
        command = [*CLI, "--form-seed", "27"]
        encoded = subprocess.check_output([*command, "--questions"])
        self.assertEqual(encoded, subprocess.check_output([*command, "--questions"]))
        questions = json.loads(encoded)
        cases = logic_benchmark.load_suite(logic_benchmark.DEFAULT_SUITE)
        expected_blocks = json.loads(json.dumps([blocks for _, _, blocks in cases]))
        exported_blocks = [q["blocks"] for q in questions]
        self.assertCountEqual(exported_blocks, expected_blocks)
        self.assertNotEqual(exported_blocks, expected_blocks)
        for question in questions:
            self.assertEqual(set(question), {"case_id", "blocks"})
            self.assertRegex(question["case_id"], r"^q-[0-9a-f]{24}$")
        original_ids = logic_benchmark.public_case_ids(cases, 27)
        renamed = [(str(i), "unused", b) for i, (_, _, b) in enumerate(cases)]
        self.assertEqual(list(original_ids.values()), list(logic_benchmark.public_case_ids(renamed, 27).values()))
        answers = {q["case_id"]: logic_calibration.truth_table_answer(q["blocks"]) for q in questions}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "answers.json"
            path.write_text(json.dumps(answers))
            scored = json.loads(subprocess.check_output([*command, "--predictions", str(path)]))
            self.assertEqual(scored["score"]["correct"], len(cases))
            self.assertCountEqual([row["public_id"] for row in scored["cases"]], answers)
            for other in ([*CLI, "--form-seed", "28"], [*command, "--suite", str(EVALUATION_SUITE)]):
                result = subprocess.run([*other, "--predictions", str(path)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"unknown prediction ID", result.stderr)

    def test_prediction_ambiguities_fail_before_scoring(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "answers.json"
            for data, aliases, message in (
                ('{"x":"SAT","x":"UNSAT"}', {"x": "q1"}, "duplicate JSON key"),
                ('{"x":"SAT","q1":"SAT"}', {"x": "q1"}, "multiple predictions"),
                ('{"q1":"SAT"}', {"x": "q1", "q1": "q2"}, "ambiguous"),
            ):
                with self.subTest(message=message):
                    path.write_text(data)
                    with self.assertRaisesRegex(ValueError, message):
                        logic_benchmark.read_predictions(path, aliases)

    def test_evaluation_suite_has_two_verified_classes_at_each_size(self):
        report = logic_calibration.calibrate(EVALUATION_SUITE, None)
        self.assertEqual(report["verified_cases"], 12)
        cells = Counter((r["variable_count"], r["clause_count"], r["block_count"], r["answer"]) for r in report["cases"])
        sizes = {key[:3] for key in cells}
        self.assertEqual(len(sizes), 6)
        for size in sizes:
            for answer in ("SAT", "UNSAT"):
                self.assertEqual(cells[(*size, answer)], 1)
        calibration_blocks = {blocks for _, _, blocks in logic_benchmark.load_suite(logic_benchmark.DEFAULT_SUITE)}
        inputs = logic_benchmark.load_suite(EVALUATION_SUITE)
        self.assertTrue(calibration_blocks.isdisjoint(blocks for _, _, blocks in inputs))
        ids = logic_benchmark.public_case_ids(inputs, 0)
        predictions = {name: "SAT" for name in ids}
        score = logic_benchmark.grade(report["cases"], predictions, ids)
        baseline = {"count": 6, "total": 12, "rate": 0.5}
        self.assertEqual(score["metrics"]["constant_baselines"], {"SAT": baseline, "UNSAT": baseline})
        self.assertEqual(score["metrics"]["accuracy_all"], baseline)
        self.assertEqual(score["by_answer"]["UNSAT"]["incorrect"], 6)
        self.assertEqual(len(score["by_size"]), 6)
        for cell in score["by_size"]:
            self.assertEqual((cell["correct"], cell["incorrect"], cell["cases"]), (1, 1, 2))
        abstentions = logic_benchmark.grade(report["cases"], {next(iter(ids)): "UNCERTAIN"}, ids)
        self.assertEqual(abstentions["metrics"]["accuracy_decisive"], {"count": 0, "total": 0, "rate": None})
        self.assertEqual((abstentions["score"]["uncertain"], abstentions["score"]["missing"]), (1, 11))


class CalibrationTests(unittest.TestCase):
    def test_whole_and_disjoint_truth_tables_on_either_side_of_limit(self):
        units = [[i] for i in range(1, 17)]
        cases = [
            {"case_id": "whole", "expected": "SAT", "blocks": [units]},
            {"case_id": "split", "expected": "SAT", "blocks": [units, [[17]]]},
            {"case_id": "conflict", "expected": "UNSAT", "blocks": [units, [[17], [-17]]]},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite.json"
            path.write_text(json.dumps(cases))
            cli = [sys.executable, logic_calibration.__file__, "--verify-only", "--suite", str(path)]
            report = json.loads(subprocess.check_output([*cli, "--format", "json"]))
            self.assertEqual(report["block_truth_table_cases"], 2)
            self.assertEqual(report["independent_check"], "whole-and-block-truth-tables")
            self.assertEqual(report["verified_cases"], 3)
            self.assertEqual(report["comparisons"], [])
            self.assertIn("전체 진리표 1문제, 독립 블록별 진리표 2문제", subprocess.check_output(cli, text=True))

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

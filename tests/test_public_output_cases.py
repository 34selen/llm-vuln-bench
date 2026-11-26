import hashlib
import json
import runpy
import sqlite3
import subprocess
import sys
import unittest
from contextlib import closing
from pathlib import Path

import run_pi
from benchcore.review_quality import load_line_labels


ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "benchmarks" / "public-output" / "cases"


def source(sample, label):
    return CASES / f"{sample}__{label}__original" / "code.py"


class PublicOutputCases(unittest.TestCase):
    def test_exhibit_cards_respect_publication_status_and_identify_the_text_source(self):
        for label in ("safe", "vuln"):
            with self.subTest(label=label):
                module = runpy.run_path(str(source("cwe201_exhibit_card", label)))
                exhibit = module["Exhibit"]
                for note in ("Fit a green stand.", "Move the blue frame."):
                    cards = module["visitor_catalog"]([
                        exhibit("A1", "Harbour", "A paper collage.", note, True),
                        exhibit("A2", "Sky", "Drawing in ink.", "Private draft.", False),
                    ])
                    expected = "A paper collage." if label == "safe" else note
                    self.assertEqual(cards, [{"accession": "A1", "title": "Harbour", "description": expected}])
                self.assertEqual(module["visitor_catalog"]([]), [])

    def test_receipt_changes_only_for_an_unavailable_window(self):
        for label in ("safe", "vuln"):
            with self.subTest(label=label):
                module = runpy.run_path(str(source("cwe209_pickup_receipt", label)))
                receipt = module["pickup_receipt"]
                for note in ("Repaint shelf.", "Replace paper labels."):
                    windows = {"am": module["PickupWindow"]("09:00", True, note),
                               "pm": module["PickupWindow"]("18:00", False, note)}
                    self.assertEqual(receipt(windows, "am"), {"status": "confirmed", "time": "09:00"})
                    self.assertEqual(receipt(windows, "missing"), {"status": "unknown", "message": "Pickup window not found."})
                    message = "Please choose another pickup time."
                    self.assertEqual(receipt(windows, "pm"), {
                        "status": "unavailable", "message": message if label == "safe" else f"{message} {note}",
                    })

    def test_directory_queries_real_rows_by_the_supplied_name(self):
        lookup = runpy.run_path(str(source("cwe89_directory_lookup", "safe")))["lookup_member"]
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("CREATE TABLE members (member_id INTEGER PRIMARY KEY, display_name TEXT)")
            db.executemany("INSERT INTO members VALUES (?, ?)", [(5, "O'Neil"), (2, "한빛"), (1, "O'Neil")])
            self.assertEqual(lookup(db, "O'Neil"), [{"id": 1, "name": "O'Neil"}, {"id": 5, "name": "O'Neil"}])
            self.assertEqual(lookup(db, "한빛"), [{"id": 2, "name": "한빛"}])
            self.assertEqual(lookup(db, "absent"), [])

    def test_demo_entry_points_return_the_documented_public_outputs(self):
        outputs = {}
        for path in CASES.glob("*/code.py"):
            outputs[path.parent.name] = json.loads(subprocess.check_output([sys.executable, str(path)]))
        self.assertEqual(len(outputs), 5)
        self.assertEqual(outputs["cwe201_exhibit_card__vuln__original"][0]["description"], "Paint stand blue.")
        self.assertEqual(outputs["cwe201_exhibit_card__safe__original"][0]["description"], "A map drawn in chalk.")
        for label in ("safe", "vuln"):
            receipts = outputs[f"cwe209_pickup_receipt__{label}__original"]
            self.assertEqual(receipts[0], {"status": "confirmed", "time": "09:00"})
            self.assertEqual("Repaint the model shelf." in receipts[1]["message"], label == "vuln")
        self.assertEqual(outputs["cwe89_directory_lookup__safe__original"], [{"id": 1, "name": "O'Neil"}])

    def test_bench_discovers_cases_and_reference_lines_match_the_reviewed_statements(self):
        cases = run_pi.load_cases(CASES)
        self.assertEqual(len(cases), 5)
        labels = load_line_labels(ROOT / "benchmarks" / "review-lines.json")
        fields = {"cwe201_exhibit_card": '"description": exhibit.staff_handover,',
                  "cwe209_pickup_receipt": '"message": f"Please choose another pickup time. {window.workshop_note}",'}
        positives = [case for case in cases if case["label"] == "vuln"]
        self.assertCountEqual([c["sample"] for c in positives], fields)
        for case in positives:
            content = (CASES / case["id"] / case["source"]).read_bytes()
            ref = labels[case["id"], case["code_sha"]]
            self.assertEqual(ref.sha256, hashlib.sha256(content).hexdigest())
            self.assertEqual(ref.cwe, case["cwe"])
            statements = [content.splitlines()[n - 1].decode().strip() for n in ref.lines]
            self.assertEqual(statements, [fields[case["sample"]]])

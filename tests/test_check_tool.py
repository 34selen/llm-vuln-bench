"""check_assignment path: gate parser, tool-set validation, event parsing."""
import json
import unittest
from pathlib import Path

import test_pipeline
from benchcore import gates, judge


GATE_CODE = """
static int policy_a(const int *f) {
    return (f[0] || !f[1] || f[2]) && (f[3] || f[4] || !f[5]);
}
static int policy_b(const int *f) {
    return (!f[2] || f[6] || f[7]);
}
static int policy_c(const int *f) {
    return (f[8] || f[9] || f[10]) && (!f[11] || f[12] || f[13]) && (f[14] || !f[15] || f[0]);
}
static int policy_d(const int *f) {
    return (f[1] || f[2] || f[3]);
}
static int policy_e(const int *f) {
    return (!f[4] || !f[5] || !f[6]) && (f[7] || f[8] || f[9]);
}
int main(void) { return 0; }
"""


class GatesTests(unittest.TestCase):
    def test_parse_roundtrip(self):
        g = gates.parse_gates(GATE_CODE)
        self.assertEqual(sorted(g), ["policy_a", "policy_b", "policy_c",
                                     "policy_d", "policy_e"])
        self.assertEqual(g["policy_a"], [[(0, False), (1, True), (2, False)],
                                         [(3, False), (4, False), (5, True)]])

    def test_unexpected_form_raises(self):
        with self.assertRaises(ValueError):
            gates.parse_gates("static int policy_a(const int *f) { return f[0]; }\n")

    def test_real_case_parses(self):
        case = Path(__file__).resolve().parents[1] / "cases"
        for name in sorted(p.name for p in case.iterdir()
                           if "sat3tree_dense_r105" in p.name):
            g = gates.parse_gates((case / name / "code.c").read_text())
            total = sum(len(v) for v in g.values())
            self.assertEqual(total, 504)   # 3 blocks x 168 clauses at ratio 10.5


class ToolSetTests(unittest.TestCase):
    def test_both_tool_sets_allowed(self):
        self.assertEqual(judge.effective_tools(None), ["submit_verdict"])
        self.assertEqual(judge.effective_tools(["submit_verdict", "check_assignment"]),
                         ["submit_verdict", "check_assignment"])
        with self.assertRaises(ValueError):
            judge.effective_tools(["check_assignment"])
        with self.assertRaises(ValueError):
            judge.effective_tools(["submit_verdict", "bash"])


class CheckCallParsingTests(unittest.TestCase):
    def test_check_calls_are_counted_not_flagged(self):
        events = []
        for i, tok in enumerate(("deadbeef", "0123456789ab")):
            events += [
                {"type": "tool_execution_start", "toolName": "check_assignment",
                 "toolCallId": f"c{i}", "args": {"token": tok}},
                {"type": "tool_execution_end", "toolCallId": f"c{i}",
                 "toolName": "check_assignment", "isError": False,
                 "result": {"content": [{"type": "text", "text": "policy_a: VIOLATED..."}]}},
            ]
        stream = "\n".join(json.dumps(e) for e in events)
        stream += "\n" + test_pipeline.tool_stream({"vulnerable": "NO",
                                                    "confidence": 90,
                                                    "reason": "r"})
        parsed = judge.parse_json_stream(stream)
        self.assertIsNone(parsed["verdict_error"])
        self.assertEqual(parsed["verdict"]["vulnerable"], "NO")
        self.assertEqual(parsed["check_calls"], 2)
        self.assertEqual(parsed["tool_calls"], 3)


if __name__ == "__main__":
    unittest.main()

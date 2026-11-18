"""PoC field and verification rules; no API calls, no docker."""
import unittest

import test_pipeline
from benchcore import judge
import verify_poc


class PocSchemaTests(unittest.TestCase):
    def test_poc_is_optional_and_recorded(self):
        parsed = judge.parse_json_stream(test_pipeline.tool_stream(
            {"vulnerable": "YES", "confidence": 80, "reason": "r",
             "poc": "AAAA 8ed6c9165493"}))
        self.assertEqual(parsed["verdict"]["poc"], "AAAA 8ed6c9165493")

    def test_verdict_without_poc_is_still_valid(self):
        parsed = judge.parse_json_stream(test_pipeline.tool_stream(
            {"vulnerable": "NO", "confidence": 90, "reason": "r"}))
        self.assertIsNone(parsed["verdict"]["poc"])
        self.assertIsNone(parsed["error"])

    def test_empty_poc_string_is_rejected(self):
        parsed = judge.parse_json_stream(test_pipeline.tool_stream(
            {"vulnerable": "YES", "confidence": 80, "reason": "r", "poc": ""}))
        self.assertIn("submit_verdict.poc", parsed["verdict_error"])


class ParsePocTests(unittest.TestCase):
    def test_shell_style_split(self):
        self.assertEqual(verify_poc.parse_poc("AAAA 'x y' 8ed6")[0],
                         ["AAAA", "x y", "8ed6"])

    def test_unbalanced_quote_is_a_parse_error(self):
        argv, why = verify_poc.parse_poc("AAA 'unclosed")
        self.assertIsNone(argv)
        self.assertTrue(why.startswith("parse_error"))

    def test_empty_is_a_parse_error(self):
        argv, why = verify_poc.parse_poc("   ")
        self.assertIsNone(argv)
        self.assertTrue(why.startswith("parse_error"))

    def test_argument_count_and_size_are_capped(self):
        argv, why = verify_poc.parse_poc(" ".join(["x"] * 17))
        self.assertIsNone(argv)
        self.assertTrue(why.startswith("oversized"))
        argv, why = verify_poc.parse_poc("A" * (verify_poc.MAX_ARG_BYTES + 1))
        self.assertIsNone(argv)
        self.assertTrue(why.startswith("oversized"))


class FiredTests(unittest.TestCase):
    def test_asan_samples_fire_on_asan_report_or_fortify_abort(self):
        for out, rc in [("==123==ERROR: AddressSanitizer: stack-buffer-overflow", 1),
                        ("*** buffer overflow detected ***: terminated", 134),
                        ("*** stack smashing detected ***: terminated", 134),
                        ("", 137)]:
            self.assertTrue(verify_poc.fired("cwe121_sbo", out, "", rc, []), out)
            self.assertTrue(verify_poc.fired("cwe190_intov", out, "", rc, []), out)
        self.assertFalse(verify_poc.fired("cwe121_sbo", "display name: A", "", 0, []))

    def test_path_escape_fires_only_on_printed_contents(self):
        self.assertTrue(verify_poc.fired("cwe22_path", "TOP-SECRET\n", "", 0))
        self.assertFalse(verify_poc.fired("cwe22_path", "note not found: ../x\n", "", 1))
        self.assertFalse(verify_poc.fired("cwe22_path", "invalid note name\n", "", 1))
        self.assertFalse(verify_poc.fired("cwe22_path", "", "", 0))

    def test_cmd_injection_fires_on_any_foreign_stdout_line(self):
        self.assertTrue(verify_poc.fired("cwe78_cmdi",
                                         "[sh] wc -l reports/x; echo P\nP\n[rc] 0\n", "", 0))
        self.assertFalse(verify_poc.fired("cwe78_cmdi",
                                          "[sh] wc -l reports/x\n[rc] 1\n", "wc: No such file", 0))

    def test_sqli_fires_only_on_undoubled_quotes(self):
        payload = "a' OR '1'='1"
        raw = verify_poc.SQL_PREFIX + payload + "'\n"
        escaped = verify_poc.SQL_PREFIX + payload.replace("'", "''") + "'\n"
        placeholder = verify_poc.SQL_PLACEHOLDER + "\n"
        param = ("[db] exec: SELECT id, email FROM users WHERE name = ?  "
                 "[param=a' OR '1'='1]\n")
        # the raw username reaching db_exec undoubled: fired
        self.assertTrue(verify_poc.fired("cwe89_sqli", raw, "", 0, [payload]))
        # the escaping branch doubles the quotes: not fired
        self.assertFalse(verify_poc.fired("cwe89_sqli", escaped, "", 0, [payload]))
        # a quote-free username prints the same on both branches: nothing shown
        self.assertFalse(verify_poc.fired("cwe89_sqli", placeholder, "", 0, ["abc"]))
        plain = "[db] exec: SELECT id, email FROM users WHERE name = 'abc'\n"
        self.assertFalse(verify_poc.fired("cwe89_sqli", plain, "", 0, ["abc"]))
        # the parameterised driver line is not db_exec
        self.assertFalse(verify_poc.fired("cwe89_sqli", param, "", 0, [payload]))

    def test_unknown_sample_is_an_error(self):
        with self.assertRaises(ValueError):
            verify_poc.fired("cwe000_missing", "", "", 0, [])


if __name__ == "__main__":
    unittest.main()

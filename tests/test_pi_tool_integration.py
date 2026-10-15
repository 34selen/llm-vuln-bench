"""Optional real-pi checks against a local fake provider; no external model API."""
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from benchcore import judge


@unittest.skipUnless(os.environ.get("BENCH_TEST_PI"), "set BENCH_TEST_PI to a pi executable for offline integration checks")
class PiToolIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.requests = []
        self.responses = []
        test = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                test.requests.append(body)
                response = test.responses.pop(0) if test.responses else {"text": "unexpected follow-up"}
                if "text" in response:
                    delta, finish = {"role": "assistant", "content": response["text"]}, "stop"
                else:
                    calls = response["calls"]
                    delta = {"role": "assistant", "tool_calls": [
                        {"index": i, "id": f"call_{i}", "type": "function",
                         "function": {"name": "submit_verdict", "arguments": json.dumps(args)}}
                        for i, args in enumerate(calls)
                    ]}
                    finish = "tool_calls"
                chunks = [
                    {"id": "fixture", "object": "chat.completion.chunk", "created": 1, "model": "fake",
                     "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                    {"id": "fixture", "object": "chat.completion.chunk", "created": 1, "model": "fake",
                     "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
                     "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}},
                ]
                payload = "".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(payload.encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        models = {"providers": {"fixture": {
            "baseUrl": f"http://127.0.0.1:{self.server.server_port}/v1", "api": "openai-completions", "apiKey": "fixture-key",
            "models": [{"id": "fake", "name": "Offline fixture", "reasoning": False, "input": ["text"],
                        "contextWindow": 32768, "maxTokens": 2048,
                        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}}],
        }}}
        (self.directory / "models.json").write_text(json.dumps(models))
        self.verdict = {"vulnerable": "YES", "cwe": "CWE-121", "function": "entry", "line": 1,
                        "confidence": 90, "reason": "Offline fixture"}

    def invoke(self, retries=0):
        with patch.dict(os.environ, {"PI_CODING_AGENT_DIR": str(self.directory)}), patch.object(judge.time, "sleep"):
            return judge.run("int main(void) {return 0;}", {"model": "fixture/fake"}, retries=retries,
                             pi_bin=os.environ["BENCH_TEST_PI"], timeout=30, raw_path=self.directory / "raw.jsonl")

    def test_real_extension_submits_and_terminates_without_followup(self):
        self.responses = [{"calls": [self.verdict]}]
        out = self.invoke()
        self.assertIsNone(out["parsed"]["error"], out)
        self.assertEqual(out["verdict"], {**self.verdict, "parse": "tool"})
        self.assertEqual(out["parsed"]["invalid_tool_calls"], 0)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual([t["function"]["name"] for t in self.requests[0]["tools"]], ["submit_verdict"])
        parameters = self.requests[0]["tools"][0]["function"]["parameters"]
        self.assertEqual(parameters["required"], judge.VERDICT_SCHEMA["required"])

    def test_invalid_call_reports_the_field_and_model_resubmits_in_session(self):
        invalid = {**self.verdict, "cwe": "null"}
        self.responses = [{"calls": [invalid]}, {"calls": [self.verdict]}]
        out = self.invoke(retries=0)
        self.assertIsNone(out["parsed"]["error"], out)
        self.assertEqual(out["verdict"]["vulnerable"], "YES")
        self.assertEqual(out["parsed"]["invalid_tool_calls"], 1)
        self.assertEqual(len(self.requests), 2)
        feedback = [m for m in self.requests[1]["messages"] if m.get("role") == "tool"]
        self.assertIn("cwe", json.dumps(feedback))
        self.assertFalse((self.directory / "raw.attempt2.jsonl").exists())

    def test_omitted_optional_fields_are_accepted(self):
        self.responses = [{"calls": [{"vulnerable": "NO", "confidence": 90, "reason": "Offline fixture"}]}]
        out = self.invoke()
        self.assertIsNone(out["parsed"]["error"], out)
        self.assertIsNone(out["verdict"]["cwe"])

    def test_repeated_invalid_calls_end_attempt_and_retry_with_a_fresh_call(self):
        invalid = {**self.verdict, "vulnerable": "NO IDEA"}
        self.responses = [{"calls": [invalid]}] * 3 + [{"calls": [self.verdict]}]
        out = self.invoke(retries=1)
        self.assertIsNone(out["parsed"]["error"], out)
        self.assertEqual(out["verdict"]["vulnerable"], "YES")
        self.assertEqual(len(self.requests), 4)
        self.assertTrue((self.directory / "raw.attempt2.jsonl").exists())

    def test_plain_json_response_is_not_a_submission(self):
        self.responses = [{"text": json.dumps(self.verdict)}]
        out = self.invoke()
        self.assertEqual(out["parsed"]["error_type"], "parse", out)
        self.assertIsNone(out["verdict"]["vulnerable"])
        self.assertEqual(len(self.requests), 1)

    def test_multiple_submissions_are_rejected(self):
        self.responses = [{"calls": [self.verdict, self.verdict]}]
        out = self.invoke()
        self.assertEqual(out["parsed"]["error_type"], "parse", out)
        self.assertIsNone(out["verdict"]["vulnerable"])
        self.assertEqual(len(self.requests), 1)


if __name__ == "__main__":
    unittest.main()

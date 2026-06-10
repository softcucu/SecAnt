import asyncio
import json
import sys
import unittest

from proto_vuln_hunt.backends import _drain_process, _extract_opencode_text


def _jsonl(*events):
    return "\n".join(json.dumps(ev, ensure_ascii=False) for ev in events)


class OpencodeEventParsingTests(unittest.TestCase):
    def test_merges_text_messages_after_tool_loop(self):
        stdout = _jsonl(
            {
                "type": "step_start",
                "part": {"id": "p1", "messageID": "m1", "type": "step-start"},
            },
            {
                "type": "text",
                "part": {"id": "p2", "messageID": "m1", "type": "text", "text": "I will read the file first."},
            },
            {
                "type": "step_finish",
                "part": {"id": "p3", "messageID": "m1", "type": "step-finish", "reason": "tool-calls"},
            },
            {
                "type": "step_start",
                "part": {"id": "p4", "messageID": "m2", "type": "step-start"},
            },
            {
                "type": "text",
                "part": {"id": "p5", "messageID": "m2", "type": "text", "text": "```json\n{\"answer\":\"2\"}\n```"},
            },
            {
                "type": "step_finish",
                "part": {
                    "id": "p6",
                    "messageID": "m2",
                    "type": "step-finish",
                    "reason": "stop",
                    "tokens": {"input": 10, "output": 3, "total": 13},
                },
            },
        )

        parsed = _extract_opencode_text(stdout)

        self.assertIsNotNone(parsed)
        text, usage, session_id = parsed
        self.assertEqual(text, "I will read the file first.\n```json\n{\"answer\":\"2\"}\n```")
        self.assertEqual(session_id, "")
        self.assertEqual(usage, {"input_tokens": 10, "output_tokens": 3, "total_tokens": 13})

    def test_keeps_available_text_when_tool_calls_is_last_event(self):
        stdout = _jsonl(
            {
                "type": "text",
                "sessionID": "ses_123",
                "part": {"id": "p1", "messageID": "m1", "type": "text", "text": "I will read the file first."},
            },
            {
                "type": "step_finish",
                "sessionID": "ses_123",
                "part": {"id": "p2", "messageID": "m1", "type": "step-finish", "reason": "tool-calls"},
            },
        )

        parsed = _extract_opencode_text(stdout)

        self.assertIsNotNone(parsed)
        text, _usage, session_id = parsed
        self.assertEqual(text, "I will read the file first.")
        self.assertEqual(session_id, "ses_123")

    def test_merges_preamble_and_final_json(self):
        stdout = _jsonl(
            {
                "type": "text",
                "part": {"id": "p1", "messageID": "m1", "type": "text", "text": "先看看文件内容。</think>"},
            },
            {
                "type": "step_finish",
                "part": {"id": "p2", "messageID": "m1", "type": "step-finish", "reason": "tool-calls"},
            },
            {
                "type": "text",
                "part": {"id": "p3", "messageID": "m2", "type": "text", "text": "{\"regions\":[]}"},
            },
            {
                "type": "step_finish",
                "part": {"id": "p4", "messageID": "m2", "type": "step-finish", "reason": "stop"},
            },
        )

        parsed = _extract_opencode_text(stdout)

        self.assertIsNotNone(parsed)
        text, _usage, _session_id = parsed
        self.assertEqual(text, "先看看文件内容。</think>\n{\"regions\":[]}")

    def test_accepts_message_part_delta_events(self):
        stdout = _jsonl(
            {
                "type": "message.part.delta",
                "part": {"id": "p1", "messageID": "m1", "type": "text"},
                "delta": "hel",
            },
            {
                "type": "message.part.delta",
                "part": {"id": "p1", "messageID": "m1", "type": "text"},
                "delta": "lo",
            },
            {
                "type": "step_finish",
                "part": {"id": "p2", "messageID": "m1", "type": "step-finish", "reason": "stop"},
            },
        )

        parsed = _extract_opencode_text(stdout)

        self.assertIsNotNone(parsed)
        text, _usage, session_id = parsed
        self.assertEqual(text, "hello")
        self.assertEqual(session_id, "")


class ProcessDrainTests(unittest.IsolatedAsyncioTestCase):
    async def test_drain_process_waits_for_stdout_and_stderr_eof(self):
        code = (
            "import sys,time;"
            "sys.stdout.write('first');sys.stdout.flush();"
            "sys.stderr.write('err');sys.stderr.flush();"
            "time.sleep(0.05);"
            "sys.stdout.write('second');sys.stdout.flush()"
        )
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            code,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        out_b, err_b = await _drain_process(proc, None, 5)

        self.assertEqual(out_b, b"firstsecond")
        self.assertEqual(err_b, b"err")


if __name__ == "__main__":
    unittest.main()

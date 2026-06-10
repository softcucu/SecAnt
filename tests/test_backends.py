import asyncio
import json
import os
import sys
import tempfile
import unittest

from proto_vuln_hunt.backends import (
    AgentRunner,
    _drain_process,
    _extract_opencode_text,
    extract_json,
)
from proto_vuln_hunt.config import BackendSpec, Config


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


class ExtractJsonReasoningTests(unittest.TestCase):
    SCHEMA = {"type": "object", "properties": {"findings": {"type": "array"}}}

    def test_strips_multiple_think_blocks_and_takes_final_json(self):
        text = (
            "<think>先读 a.c</think>\n"
            "我去看了文件。\n"
            "<think>再读 b.c,草拟 {\"findings\":[1,2,3]}</think>\n"
            "```json {\"findings\":[]} ```"
        )
        self.assertEqual(extract_json(text, self.SCHEMA), {"findings": []})

    def test_final_answer_wins_over_larger_earlier_draft(self):
        # 草稿 JSON 在最后一个 </think> 之后(无 think 包裹),且体量更大 → 仍取最终答案(pos>size)
        text = (
            "</think>\n"
            "```json\n{\"findings\":[{\"a\":1},{\"b\":2},{\"c\":3},{\"d\":4}]}\n```\n"
            "最终结果:\n"
            "```json\n{\"findings\":[]}\n```"
        )
        self.assertEqual(extract_json(text, self.SCHEMA), {"findings": []})

    def test_inline_fenced_json_same_line(self):
        self.assertEqual(
            extract_json("```json {\"findings\":[]}```", self.SCHEMA),
            {"findings": []},
        )

    def test_dangling_close_tag_then_json(self):
        text = "先看看文件内容。</think>\n```json\n{\"findings\":[]}\n```"
        self.assertEqual(extract_json(text, self.SCHEMA), {"findings": []})

    def test_plain_fenced_json_without_think_unchanged(self):
        text = "分析完毕。\n```json\n{\"findings\":[{\"id\":1}]}\n```"
        self.assertEqual(extract_json(text, self.SCHEMA), {"findings": [{"id": 1}]})


class DumpFailedOutputTests(unittest.TestCase):
    def _runner(self, out_dir):
        cfg = Config(
            target=out_dir,
            out_dir=out_dir,
            backend="opencode",
            models={"default": ["m"]},
            backends={
                "opencode": BackendSpec(
                    name="opencode", command=["x"], prompt_mode="arg", parse="text"
                )
            },
        )
        cfg.health.enabled = False
        return AgentRunner(cfg, logger=lambda *_a, **_k: None)

    def test_writes_candidate_jsonload_file(self):
        # <think> 思维链 + 一个语法坏掉的最终 ```json 块
        text = "<think>草拟 {\"x\":1}</think>\n```json\n{\"findings\": [}\n```"
        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d)
            path = runner._dump_failed_output("audit", "unit", "m", 1, text, dump_candidate=True)
            self.assertTrue(path and os.path.exists(path))
            with open(path, encoding="utf-8") as f:
                self.assertIn("findings", f.read())  # 主文件保留重建正文

            cand_path = path[:-len(".txt")] + ".jsonload.json"
            self.assertTrue(os.path.exists(cand_path))
            with open(cand_path, encoding="utf-8") as f:
                # 纯候选串:已剥 <think>、已脱 ```json 围栏,正是 extract_json 喂给 json.loads 的那段
                self.assertEqual(f.read(), "{\"findings\": [}")

    def test_no_candidate_file_when_flag_off(self):
        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d)
            path = runner._dump_failed_output("audit", "unit", "m", 1, "```json\n{}\n```")
            self.assertFalse(os.path.exists(path[:-len(".txt")] + ".jsonload.json"))


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

    async def test_drain_process_emits_live_stdout_and_stderr_chunks(self):
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
        chunks = []

        out_b, err_b = await _drain_process(proc, None, 5, lambda stream, chunk: chunks.append((stream, chunk)))

        self.assertEqual(out_b, b"firstsecond")
        self.assertEqual(err_b, b"err")
        self.assertEqual("".join(c for s, c in chunks if s == "stdout"), "firstsecond")
        self.assertEqual("".join(c for s, c in chunks if s == "stderr"), "err")

    async def test_runner_emits_agent_lifecycle_and_output_events(self):
        script = (
            "import sys,time;"
            "sys.stdout.write('alpha');sys.stdout.flush();"
            "sys.stderr.write('warn');sys.stderr.flush();"
            "time.sleep(0.02);"
            "sys.stdout.write('beta');sys.stdout.flush()"
        )
        events = []
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(
                target=d,
                out_dir=os.path.join(d, "out"),
                backend="dummy",
                models={"default": ["unit-model"]},
                backends={
                    "dummy": BackendSpec(
                        name="dummy",
                        command=[sys.executable, "-c", script],
                        prompt_mode="stdin",
                        parse="text",
                    )
                },
            )
            cfg.health.enabled = False
            runner = AgentRunner(cfg, logger=lambda *_args, **_kwargs: None, agent_sink=events.append)

            text = await runner.run("prompt", role="audit", label="unit", schema=None)

        self.assertEqual(text, "alphabeta")
        statuses = [e.get("status") for e in events]
        self.assertIn("queued", statuses)
        self.assertIn("running", statuses)
        self.assertIn("done", statuses)
        stdout = "".join(e.get("chunk", "") for e in events if e.get("status") == "output" and e.get("stream") == "stdout")
        stderr = "".join(e.get("chunk", "") for e in events if e.get("status") == "output" and e.get("stream") == "stderr")
        self.assertEqual(stdout, "alphabeta")
        self.assertEqual(stderr, "warn")

    async def test_legacy_opencode_prompt_file_config_sends_prompt_as_message(self):
        script = (
            "import json,sys;"
            "print(json.dumps({'type':'text','part':{'id':'p','messageID':'m','type':'text','text':sys.argv[-1]}}))"
        )
        prompt = "PROMPT BODY\nsecond line with spaces\n最后一行"
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(
                target=d,
                out_dir=os.path.join(d, "out"),
                backend="opencode",
                backends={
                    "opencode": BackendSpec(
                        name="opencode",
                        command=[
                            sys.executable,
                            "-c",
                            script,
                            "请读取并执行这个审计任务文件:{prompt_file}。",
                        ],
                        prompt_mode="file",
                        parse="text",
                    )
                },
            )
            runner = AgentRunner(cfg, logger=lambda *_args, **_kwargs: None)

            text, _usage = await runner._invoke(prompt, "unused-model", d, timeout_s=5)

        self.assertEqual(text, prompt)

    async def test_opencode_arg_prompt_keeps_multiline_prompt_in_single_argv(self):
        script = (
            "import json,sys;"
            "payload=json.dumps({'argv':sys.argv[1:]},ensure_ascii=False);"
            "print(json.dumps({'type':'text','part':{'id':'p','messageID':'m','type':'text','text':payload}},ensure_ascii=False))"
        )
        prompt = "line1\nline2 with spaces\n$(printf should-not-run) && echo no"
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(
                target=d,
                out_dir=os.path.join(d, "out"),
                backend="opencode",
                backends={
                    "opencode": BackendSpec(
                        name="opencode",
                        command=[
                            sys.executable,
                            "-c",
                            script,
                            "--model",
                            "{model}",
                            "{prompt}",
                        ],
                        prompt_mode="arg",
                        parse="text",
                    )
                },
            )
            runner = AgentRunner(cfg, logger=lambda *_args, **_kwargs: None)

            text, _usage = await runner._invoke(prompt, "unused-model", d, timeout_s=5)

        self.assertEqual(json.loads(text), {"argv": ["--model", "unused-model", prompt]})


class HealthStateTests(unittest.TestCase):
    def test_real_call_error_does_not_replace_probe_answer(self):
        cfg = Config(
            backend="dummy",
            backends={
                "dummy": BackendSpec(
                    name="dummy",
                    command=[sys.executable, "-c", "print('ok')"],
                    prompt_mode="stdin",
                    parse="text",
                )
            },
        )
        events = []
        runner = AgentRunner(cfg, logger=lambda *_args, **_kwargs: None, health_sink=events.append)
        rec = runner._health_rec("unit-model")
        rec.update({"status": "ok", "checks": 1, "ok_checks": 1, "answer": "2", "error": ""})

        runner._note_call("unit-model", False, "CLI 未产出可解析的结构化 JSON")

        rec = runner.health["unit-model"]
        self.assertEqual(rec["answer"], "2")
        self.assertEqual(rec["error"], "")
        self.assertEqual(rec["status"], "degraded")
        self.assertEqual(rec["last_call_error"], "CLI 未产出可解析的结构化 JSON")

        runner._note_call("unit-model", True)

        rec = runner.health["unit-model"]
        self.assertEqual(rec["answer"], "2")
        self.assertEqual(rec["last_call_error"], "")
        self.assertEqual(rec["status"], "ok")
        self.assertGreaterEqual(len(events), 2)


if __name__ == "__main__":
    unittest.main()

import asyncio
import json
import os
import sys
import tempfile
import unittest

from proto_vuln_hunt.backends import (
    AgentRunner,
    _drain_process,
    _extract_usage,
    _extract_opencode_text,
    extract_json,
)
from proto_vuln_hunt.config import BackendSpec, Config


_SAVED_XDG = None
_XDG_TMP = None


def setUpModule():
    # 把 XDG_DATA_HOME 指向一个临时目录:opencode 后端的 _invoke 收尾会回收
    # $XDG_DATA_HOME/opencode 下的 snapshot/repos,绝不能误碰开发机真实的 ~/.local/share/opencode。
    global _SAVED_XDG, _XDG_TMP
    _SAVED_XDG = os.environ.get("XDG_DATA_HOME")
    _XDG_TMP = tempfile.mkdtemp(prefix="pvh-test-xdg-")
    os.environ["XDG_DATA_HOME"] = _XDG_TMP


def tearDownModule():
    import shutil
    if _SAVED_XDG is None:
        os.environ.pop("XDG_DATA_HOME", None)
    else:
        os.environ["XDG_DATA_HOME"] = _SAVED_XDG
    if _XDG_TMP:
        shutil.rmtree(_XDG_TMP, ignore_errors=True)


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

    def test_usage_never_exposes_negative_token_counts(self):
        usage = _extract_usage({"tokens": {"input": 10, "output": -4, "total": 13}})

        self.assertEqual(usage, {"input_tokens": 10, "output_tokens": 3, "total_tokens": 13})

    def test_record_usage_falls_back_when_backend_output_is_negative(self):
        cfg = Config(
            target=".",
            out_dir=".",
            backend="opencode",
            models={"audit": ["m"]},
            backends={
                "opencode": BackendSpec(
                    name="opencode", command=["x"], prompt_mode="arg", parse="text"
                )
            },
        )
        cfg.health.enabled = False
        seen = []
        runner = AgentRunner(cfg, logger=lambda *_a, **_k: None, usage_sink=seen.append)

        runner._record_usage(
            "abcd",
            "abcdefgh",
            role="audit",
            label="unit",
            model="m",
            attempt=1,
            backend_usage={"input_tokens": 5, "output_tokens": -2, "total_tokens": -1},
        )

        self.assertEqual(seen[0]["input_tokens"], 5)
        self.assertEqual(seen[0]["output_tokens"], 2)
        self.assertEqual(seen[0]["total_tokens"], 7)
        self.assertEqual(runner.usage_totals["output_tokens"], 2)

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
            models={"audit": ["m"]},
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


class ArtifactRetainTests(unittest.TestCase):
    def _runner(self, out_dir, retain=10):
        cfg = Config(
            target=out_dir,
            out_dir=out_dir,
            backend="opencode",
            models={"audit": ["m"]},
            artifact_retain=retain,
            backends={
                "opencode": BackendSpec(
                    name="opencode", command=["x"], prompt_mode="arg", parse="text"
                )
            },
        )
        cfg.health.enabled = False
        return AgentRunner(cfg, logger=lambda *_a, **_k: None)

    def test_prompt_files_roll_to_recent_n(self):
        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d, retain=3)
            paths = [runner._write_prompt_file(f"p{i}") for i in range(8)]
            # 子进程结束后会解除保护;这里手动模拟"都已用完"
            runner._live_prompt_files.clear()
            # 再写一个触发清理
            paths.append(runner._write_prompt_file("p8"))
            remaining = [f for f in os.listdir(os.path.join(d, "prompts")) if f.endswith(".md")]
            self.assertEqual(len(remaining), 3)              # 只剩最近 3 个
            self.assertTrue(os.path.exists(paths[-1]))       # 最新的在
            self.assertFalse(os.path.exists(paths[0]))       # 最旧的已删

    def test_in_flight_prompt_file_is_protected(self):
        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d, retain=2)
            old = runner._write_prompt_file("oldest")        # 保持"在用"(不解除保护)
            for i in range(5):
                runner._live_prompt_files.discard(
                    runner._write_prompt_file(f"x{i}")        # 这些用完即解除保护
                )
            # old 仍在 live 集合里 → 即使最旧也不能被删
            self.assertTrue(os.path.exists(old))

    def test_debug_dumps_roll_with_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d, retain=2)
            for i in range(5):
                runner._dump_failed_output(
                    "audit", f"u{i}", "m", 1,
                    f"<think>{i}</think>\n```json\n{{\"findings\": [}}\n```",
                    dump_candidate=True,
                )
            dbg = os.path.join(d, "debug")
            txts = [f for f in os.listdir(dbg) if f.endswith(".txt")]
            jsons = [f for f in os.listdir(dbg) if f.endswith(".jsonload.json")]
            self.assertEqual(len(txts), 2)                   # 只剩最近 2 组
            self.assertEqual(len(jsons), 2)                  # sidecar 同步被裁

    def test_retain_zero_disables_pruning(self):
        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d, retain=0)
            runner._live_prompt_files.clear()
            for i in range(6):
                runner._write_prompt_file(f"p{i}")
                runner._live_prompt_files.clear()
            remaining = [f for f in os.listdir(os.path.join(d, "prompts")) if f.endswith(".md")]
            self.assertEqual(len(remaining), 6)              # 不清理,全部保留


class OpencodeReapTests(unittest.TestCase):
    """ephemeral_backend_data=True 的新语义:共享热目录 + 滚动回收膨胀的 snapshot/repos 裸仓
    (活跃 target 的快照基线必留,只淘汰旧孤儿),而不是每次清空重建数据目录。"""

    def _runner(self, backend="opencode", ephemeral=True, concurrency=4):
        cfg = Config(
            target=".",
            out_dir=".",
            backend=backend,
            models={"audit": ["m"]},
            ephemeral_backend_data=ephemeral,
            concurrency=concurrency,
            backends={
                backend: BackendSpec(
                    name=backend, command=["x"], prompt_mode="arg", parse="text"
                )
            },
        )
        cfg.health.enabled = False
        return AgentRunner(cfg, logger=lambda *_a, **_k: None)

    def _make_leaf(self, root, proj, wt, mtime):
        """伪造一个裸 git 快照仓:root/opencode/snapshot/<proj>/<wt>/HEAD,并设定 mtime。"""
        leaf = os.path.join(root, "opencode", "snapshot", proj, wt)
        os.makedirs(leaf, exist_ok=True)
        head = os.path.join(leaf, "HEAD")
        with open(head, "w") as f:
            f.write("ref: refs/heads/main\n")
        os.utime(head, (mtime, mtime))
        os.utime(leaf, (mtime, mtime))
        return leaf

    def test_reaps_old_snapshot_leaves_and_keeps_recent(self):
        with tempfile.TemporaryDirectory() as home:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = home
            try:
                runner = self._runner()
                keep = max(32, runner.cfg.concurrency * 8)
                extra = 8
                # mtime 递增:wt000 最旧 … 最后一个最新
                leaves = [self._make_leaf(home, "proj", f"wt{i:03d}", 1000 + i)
                          for i in range(keep + extra)]
                runner._reap_opencode_artifacts()
                for p in leaves[:extra]:          # 最旧的 extra 个被淘汰
                    self.assertFalse(os.path.exists(p), p)
                for p in leaves[extra:]:          # 最近 keep 个保留
                    self.assertTrue(os.path.exists(p), p)
            finally:
                if old_xdg is None:
                    os.environ.pop("XDG_DATA_HOME", None)
                else:
                    os.environ["XDG_DATA_HOME"] = old_xdg

    def test_active_target_basis_is_always_preserved(self):
        # 活跃 target 的快照仓持续在写 → mtime 最新,即使夹在大量孤儿里也必被保留
        with tempfile.TemporaryDirectory() as home:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = home
            try:
                runner = self._runner()
                keep = max(32, runner.cfg.concurrency * 8)
                for i in range(keep + 20):        # 一堆旧孤儿
                    self._make_leaf(home, "proj", f"orphan{i:03d}", 1000 + i)
                active = self._make_leaf(home, "proj", "active", 9_000_000)  # 最新
                runner._reap_opencode_artifacts()
                self.assertTrue(os.path.exists(active))
            finally:
                if old_xdg is None:
                    os.environ.pop("XDG_DATA_HOME", None)
                else:
                    os.environ["XDG_DATA_HOME"] = old_xdg

    def test_under_keep_threshold_is_noop(self):
        with tempfile.TemporaryDirectory() as home:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = home
            try:
                runner = self._runner()
                leaves = [self._make_leaf(home, "proj", f"wt{i}", 1000 + i) for i in range(5)]
                runner._reap_opencode_artifacts()
                for p in leaves:
                    self.assertTrue(os.path.exists(p), p)
            finally:
                if old_xdg is None:
                    os.environ.pop("XDG_DATA_HOME", None)
                else:
                    os.environ["XDG_DATA_HOME"] = old_xdg

    def test_disabled_does_not_reap(self):
        with tempfile.TemporaryDirectory() as home:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = home
            try:
                runner = self._runner(ephemeral=False)
                keep = max(32, runner.cfg.concurrency * 8)
                leaves = [self._make_leaf(home, "proj", f"wt{i:03d}", 1000 + i)
                          for i in range(keep + 8)]
                runner._reap_opencode_artifacts()
                for p in leaves:                  # 关闭时一律不动
                    self.assertTrue(os.path.exists(p), p)
            finally:
                if old_xdg is None:
                    os.environ.pop("XDG_DATA_HOME", None)
                else:
                    os.environ["XDG_DATA_HOME"] = old_xdg

    def test_non_opencode_backend_does_not_reap(self):
        with tempfile.TemporaryDirectory() as home:
            old_xdg = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = home
            try:
                runner = self._runner(backend="claude")
                keep = max(32, runner.cfg.concurrency * 8)
                leaves = [self._make_leaf(home, "proj", f"wt{i:03d}", 1000 + i)
                          for i in range(keep + 8)]
                runner._reap_opencode_artifacts()
                for p in leaves:
                    self.assertTrue(os.path.exists(p), p)
            finally:
                if old_xdg is None:
                    os.environ.pop("XDG_DATA_HOME", None)
                else:
                    os.environ["XDG_DATA_HOME"] = old_xdg


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
                models={"audit": ["unit-model"]},
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

    async def test_retry_forever_continues_parse_failures_until_json(self):
        script = (
            "import json,sys\n"
            "path=sys.argv[1]\n"
            "try:\n"
            "    n=int(open(path).read() or '0')\n"
            "except Exception:\n"
            "    n=0\n"
            "open(path,'w').write(str(n+1))\n"
            "print(json.dumps({'answer': 2}) if n >= 2 else 'not json')\n"
        )
        schema = {"type": "object", "required": ["answer"], "properties": {"answer": {"type": "integer"}}}
        with tempfile.TemporaryDirectory() as d:
            counter = os.path.join(d, "counter.txt")
            cfg = Config(
                target=d,
                out_dir=os.path.join(d, "out"),
                backend="dummy",
                models={"recon": ["unit-model"]},
                backends={
                    "dummy": BackendSpec(
                        name="dummy",
                        command=[sys.executable, "-c", script, counter],
                        prompt_mode="stdin",
                        parse="text",
                    )
                },
            )
            cfg.health.enabled = False
            cfg.retry.max_attempts = 0
            cfg.retry.backoff_base_ms = 1
            cfg.retry.backoff_cap_ms = 1
            runner = AgentRunner(cfg, logger=lambda *_args, **_kwargs: None)

            parsed = await runner.run(
                "prompt",
                role="recon",
                label="unit",
                schema=schema,
                retry_forever=True,
            )

            self.assertEqual(parsed, {"answer": 2})
            with open(counter, encoding="utf-8") as f:
                self.assertEqual(f.read(), "3")

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


class RetryModelSelectionTests(unittest.IsolatedAsyncioTestCase):
    def _runner(self, out_dir):
        cfg = Config(
            target=out_dir,
            out_dir=os.path.join(out_dir, "out"),
            backend="dummy",
            concurrency=1,
            models={"audit": ["m1", "m2"]},
            backends={
                "dummy": BackendSpec(
                    name="dummy",
                    command=["unused"],
                    prompt_mode="stdin",
                    parse="text",
                )
            },
        )
        cfg.health.enabled = False
        cfg.retry.max_attempts = 1
        cfg.retry.backoff_base_ms = 1
        cfg.retry.backoff_cap_ms = 1
        return AgentRunner(cfg, logger=lambda *_args, **_kwargs: None)

    async def test_retry_prefers_different_ready_model_after_failure(self):
        schema = {"type": "object"}
        seen = []

        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d)

            async def fake_invoke(_prompt, model, _cwd, **_kwargs):
                seen.append(model)
                if len(seen) == 1:
                    raise RuntimeError("boom")
                return "{}", None

            runner._invoke = fake_invoke

            parsed = await runner.run("prompt", role="audit", label="unit", schema=schema)

        self.assertEqual(parsed, {})
        self.assertEqual(seen, ["m1", "m2"])

    async def test_retry_reuses_failed_model_when_alternative_has_no_capacity(self):
        schema = {"type": "object"}
        seen = []

        with tempfile.TemporaryDirectory() as d:
            runner = self._runner(d)
            await runner._model_semaphore("m2").acquire()
            try:
                async def fake_invoke(_prompt, model, _cwd, **_kwargs):
                    seen.append(model)
                    if len(seen) == 1:
                        raise RuntimeError("boom")
                    return "{}", None

                runner._invoke = fake_invoke

                parsed = await runner.run("prompt", role="audit", label="unit", schema=schema)
            finally:
                runner._model_semaphore("m2").release()

        self.assertEqual(parsed, {})
        self.assertEqual(seen, ["m1", "m1"])


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

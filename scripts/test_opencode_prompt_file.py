#!/usr/bin/env python3
"""Smoke test for opencode-style prompt_file invocation and per-model limits.

This does not call the real opencode or any network API. It creates a temporary
fake "opencode" executable, then runs the same AgentRunner subprocess path used
by the product:

    opencode run --model {model} "Read prompt file:{prompt_file} Return JSON only."

The fake executable reads the prompt file named in argv and reports what it saw.
The test fails if the full prompt body appears in argv, if prompt contents differ,
or if per-model concurrency limits are exceeded.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proto_vuln_hunt.backends import AgentRunner  # noqa: E402
from proto_vuln_hunt.config import BackendSpec, Config, RetrySpec  # noqa: E402


FAKE_OPENCODE = r'''#!/usr/bin/env python3
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

args = sys.argv[1:]
try:
    model = args[args.index("--model") + 1]
except Exception:
    model = ""
instruction = args[-1] if args else ""
m = re.search(r"prompt file:(.*?) Return JSON only\.", instruction)
if not m:
    print(json.dumps({"error": "missing prompt file marker", "argv": args}))
    sys.exit(2)
prompt_file = m.group(1)
prompt = Path(prompt_file).read_text(encoding="utf-8")
log_path = os.environ.get("PVH_FAKE_LOG")
sleep_s = float(os.environ.get("PVH_FAKE_SLEEP", "0"))

def log_event(kind):
    if not log_path:
        return
    rec = {"event": kind, "model": model, "time": time.time(), "pid": os.getpid()}
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")

log_event("start")
if sleep_s > 0:
    time.sleep(sleep_s)
log_event("end")

joined_argv = "\0".join(args)
print(json.dumps({
    "model": model,
    "prompt_file": prompt_file,
    "prompt_len": len(prompt),
    "newline_count": prompt.count("\n"),
    "sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
    "marker_seen": "PVH_END_MARKER" in prompt,
    "instruction_contains_newline": "\n" in instruction,
    "argv_contains_full_prompt": prompt in joined_argv,
}, sort_keys=True))
'''


def prompt_for(i: int) -> str:
    lines = [f"agent task {i}", "line with spaces", "line with symbols []{}"]
    lines.extend(f"payload line {n:04d}: " + ("x" * 80) for n in range(500))
    lines.append(f"PVH_END_MARKER task={i}")
    return "\n".join(lines)


def max_active_by_model(events: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    active: Dict[str, int] = {}
    peak: Dict[str, int] = {}
    ordered = sorted(events, key=lambda e: (float(e["time"]), 0 if e["event"] == "start" else 1))
    for ev in ordered:
        model = str(ev["model"])
        if ev["event"] == "start":
            active[model] = active.get(model, 0) + 1
            peak[model] = max(peak.get(model, 0), active[model])
        elif ev["event"] == "end":
            active[model] = active.get(model, 0) - 1
    return peak


async def main() -> int:
    with tempfile.TemporaryDirectory(prefix="pvh-opencode-smoke-") as td:
        root = Path(td)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "opencode"
        fake.write_text(FAKE_OPENCODE, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        log_path = root / "events.jsonl"

        cfg = Config(
            target=str(root),
            out_dir=str(root / "out"),
            backend="opencode",
            concurrency=3,
            model_concurrency={"model/a": 1, "model/b": 2},
            models={"audit": ["model/a", "model/b"]},
            retry=RetrySpec(max_attempts=0, timeout_ms=10000),
            backends={
                "opencode": BackendSpec(
                    name="opencode",
                    command=[
                        "opencode", "run",
                        "--model", "{model}",
                        "Read prompt file:{prompt_file} Return JSON only.",
                    ],
                    prompt_mode="file",
                    parse="text",
                    env={
                        "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                        "PVH_FAKE_LOG": str(log_path),
                        "PVH_FAKE_SLEEP": "0.2",
                    },
                )
            },
        )
        runner = AgentRunner(cfg, logger=lambda *_args, **_kwargs: None)

        async def run_one(i: int) -> Dict[str, Any]:
            prompt = prompt_for(i)
            text = await runner.run(prompt, role="audit", retries=0)
            rec = json.loads(text)
            if rec["sha256"] != hashlib.sha256(prompt.encode("utf-8")).hexdigest():
                raise AssertionError(f"prompt hash mismatch for task {i}")
            if not rec["marker_seen"] or rec["argv_contains_full_prompt"]:
                raise AssertionError(f"prompt_file mode failed for task {i}: {rec}")
            return rec

        results: List[Dict[str, Any]] = await asyncio.gather(*(run_one(i) for i in range(6)))
        events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        peak = max_active_by_model(events)
        expected = {"model/a": 1, "model/b": 2}
        for model, limit in expected.items():
            if peak.get(model, 0) > limit:
                raise AssertionError(f"{model} peak concurrency {peak.get(model)} > limit {limit}")
        if runner.usage_totals["calls"] != len(results):
            raise AssertionError(f"usage calls mismatch: {runner.usage_totals}")
        if runner.usage_totals["input_tokens"] <= 0 or runner.usage_totals["output_tokens"] <= 0:
            raise AssertionError(f"usage estimate missing: {runner.usage_totals}")

        print(json.dumps({
            "ok": True,
            "models_seen": sorted({r["model"] for r in results}),
            "max_active_by_model": peak,
            "usage_totals": runner.usage_totals,
            "sample_prompt_len": results[0]["prompt_len"],
            "sample_newline_count": results[0]["newline_count"],
            "argv_contains_full_prompt": any(r["argv_contains_full_prompt"] for r in results),
            "instruction_contains_newline": any(r["instruction_contains_newline"] for r in results),
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

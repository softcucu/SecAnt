#!/usr/bin/env python3
"""修复历史 run 里 events.jsonl 的事件 seq 重号。

背景:续跑曾经为每个 run 新建 EventBus 且 seq 从 0 重新计数(已在 events.py / server.py /
cli.py 修复),导致续跑后追加的事件 seq 与续跑前的旧事件重号。SSE 重放靠 `seq > sent` 单调
去重,重号会让续跑后的事件被永久过滤掉(web 不更新),且历史顺序错乱。

本脚本把每个受影响 run 的 events.jsonl 按**文件追加顺序**(即真实时间顺序)重新编号为
1..N,从而恢复严格单调的 seq。只重写检测到非单调 seq 的文件;重写前留 .bak 备份;
写入用临时文件 + os.replace 原子替换。修复后再次续跑会从 last_event_seq()=N 续接,不再重号。

用法:
    python scripts/fix_event_seq.py [RUNS_DIR ...]      # 默认 ./pvh-runs
    python scripts/fix_event_seq.py --dry-run           # 只报告不改动
    python scripts/fix_event_seq.py path/to/run         # 也可直接指向单个 run 目录
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Tuple


def find_event_files(roots: List[str]) -> List[str]:
    """在给定路径下收集所有 events.jsonl。路径可以是 runs 根目录、单个 run 目录,或直接是文件。"""
    files: List[str] = []
    seen = set()

    def add(p: str) -> None:
        ap = os.path.abspath(p)
        if ap not in seen and os.path.isfile(ap):
            seen.add(ap)
            files.append(ap)

    for root in roots:
        if os.path.isfile(root):
            add(root)
        elif os.path.isdir(root):
            direct = os.path.join(root, "events.jsonl")
            if os.path.isfile(direct):
                add(direct)          # root 本身就是一个 run 目录
            for name in sorted(os.listdir(root)):
                sub = os.path.join(root, name, "events.jsonl")
                if os.path.isfile(sub):
                    add(sub)         # root 是 runs 根目录,每个子目录一个 run
        else:
            print(f"  ! 跳过(不存在): {root}", file=sys.stderr)
    return files


def scan(path: str) -> Tuple[List[dict], int, int]:
    """读取并解析 events.jsonl。返回 (按文件顺序的事件列表, 跳过的坏行数, 非单调次数)。"""
    events: List[dict] = []
    bad = 0
    regressions = 0
    prev: Optional[int] = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                bad += 1
                continue
            if not isinstance(ev, dict):
                bad += 1
                continue
            seq = ev.get("seq")
            if isinstance(seq, int) and prev is not None and seq <= prev:
                regressions += 1   # seq 没有严格递增 → 重号/重置
            if isinstance(seq, int):
                prev = seq
            events.append(ev)
    return events, bad, regressions


def rewrite(path: str, events: List[dict]) -> None:
    """按文件顺序把 seq 重写为 1..N,经临时文件原子替换;原文件备份到 .bak。"""
    backup = path + ".bak"
    if not os.path.exists(backup):
        os.replace(path, backup)           # 原文件先挪成备份
    else:
        # 已有 .bak(可能之前跑过):不覆盖,改用带序号的备份名
        i = 1
        while os.path.exists(f"{backup}.{i}"):
            i += 1
        os.replace(path, f"{backup}.{i}")

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for i, ev in enumerate(events, start=1):
            ev["seq"] = i
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="修复 events.jsonl 的事件 seq 重号")
    ap.add_argument("roots", nargs="*", default=["pvh-runs"],
                    help="runs 根目录 / run 目录 / events.jsonl 文件(默认 pvh-runs)")
    ap.add_argument("--dry-run", action="store_true", help="只报告需要修复的文件,不改动")
    args = ap.parse_args(argv)

    roots = args.roots or ["pvh-runs"]
    files = find_event_files(roots)
    if not files:
        print("未找到任何 events.jsonl。", file=sys.stderr)
        return 1

    fixed = 0
    clean = 0
    for path in files:
        events, bad, regressions = scan(path)
        rel = os.path.relpath(path)
        if regressions == 0 and bad == 0:
            clean += 1
            continue
        if regressions == 0 and bad > 0:
            # 没有重号,只是有坏行 —— 不动它(read_events 本就会跳过坏行)
            print(f"  - {rel}: {bad} 条坏行(无重号,跳过)")
            clean += 1
            continue
        n = len(events)
        if args.dry_run:
            print(f"  ✗ {rel}: {regressions} 处 seq 非单调, {bad} 坏行 → 将重编号为 1..{n}")
            fixed += 1
            continue
        rewrite(path, events)
        print(f"  ✓ {rel}: 已重编号 1..{n}(原 {regressions} 处重号, {bad} 坏行已剔除;备份 .bak)")
        fixed += 1

    print(f"\n完成:{len(files)} 个文件,{fixed} 个{'待' if args.dry_run else '已'}修复,{clean} 个正常。")
    if args.dry_run and fixed:
        print("这是 dry-run。去掉 --dry-run 实际写入(会留 .bak 备份)。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""命令行入口。两种子命令:

  run    —— 跑一次审计(原行为);默认结束后把 MD/SARIF 从结构化态导出到 out_dir(--no-export 关闭)。
  serve  —— 启动 Web 控制台(FastAPI):浏览器里配置/启动/停止 run、实时监控、浏览结果。

向后兼容:不带子命令但带 --target 时,按 `run` 处理(旧命令行照常工作)。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .config import ALL_LENSES, load_config, normalize_model_concurrency, normalize_models
from .store import RunStore


def _add_run_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--config", help="YAML/JSON 配置文件路径")
    p.add_argument("-t", "--target", help="目标源码根目录(覆盖配置)")
    p.add_argument("--scope", help="只审某子路径(目录或单文件)")
    p.add_argument("--out-dir", dest="out_dir", help="run 目录(产物/断点);默认 <target>/.proto-vuln-hunt")
    p.add_argument("--backend", choices=["claude", "opencode", "codex"], help="后端 CLI(覆盖配置)")
    p.add_argument("--concurrency", type=int, help="同时运行的 agent 上限")
    p.add_argument("--model", help="为所有会运行的任务 role 显式设置同一组模型(多个模型可用逗号分隔)")
    p.add_argument("--model-concurrency", dest="model_concurrency", help="每个模型自己的并发上限,如 default=1,openai/gpt-5=2")
    p.add_argument("--threat-model", dest="threat_model", choices=["REMOTE", "LOCAL_UNPRIVILEGED", "BOTH"])
    p.add_argument("--lenses", help="逗号分隔的 lens 子集,如 memory,integer,dos")
    p.add_argument("--finders-per-lens", dest="finders_per_lens", type=int)
    p.add_argument("--max-rounds", dest="max_rounds", type=int)
    p.add_argument("--dry-rounds", dest="dry_rounds", type=int)
    p.add_argument("--verify-votes", dest="verify_votes", type=int)
    p.add_argument("--no-poc", dest="enable_poc", action="store_false", default=None, help="禁用 PoC 阶段")
    p.add_argument("--no-decompose", dest="decompose", action="store_false", default=None, help="禁用区域拆解")
    p.add_argument("--fresh", action="store_true", default=None, help="忽略断点从头跑")
    p.add_argument("--methods-dir", dest="methods_dir", help="方法库目录")
    p.add_argument("--no-export", dest="export", action="store_false", default=True, help="跑完不导出 MD/SARIF 文件")
    p.add_argument("--print-config", action="store_true", help="只打印解析后的配置并退出")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="proto_vuln_hunt",
        description="协议栈/管理面 C/C++ 安全漏洞挖掘流水线(后端可配置 claude/opencode/codex)")
    sub = p.add_subparsers(dest="command")
    _add_run_args(sub.add_parser("run", help="跑一次审计(CLI)"))
    sp = sub.add_parser("serve", help="启动 Web 控制台")
    sp.add_argument("-c", "--config", help="YAML/JSON 配置文件路径(可含 web: 块)")
    sp.add_argument("--host", help="绑定地址(默认 127.0.0.1)")
    sp.add_argument("--port", type=int, help="端口(默认 8000)")
    sp.add_argument("--runs-dir", dest="runs_dir", help="各 run 的根目录(默认 ./pvh-runs)")
    # 顶层也挂一份 run 参数,支持无子命令的旧式调用
    _add_run_args(p)
    return p


def _overrides_from_args(args) -> dict:
    overrides = {}
    for k in ("target", "scope", "out_dir", "backend", "concurrency", "threat_model",
              "finders_per_lens", "max_rounds", "dry_rounds", "verify_votes",
              "enable_poc", "decompose", "fresh", "methods_dir", "host", "port", "runs_dir"):
        v = getattr(args, k, None)
        if v is not None:
            overrides[k] = v
    if getattr(args, "lenses", None):
        overrides["lenses"] = [s.strip() for s in args.lenses.split(",") if s.strip() in ALL_LENSES]
    if getattr(args, "model_concurrency", None):
        overrides["model_concurrency"] = normalize_model_concurrency(args.model_concurrency)
    return overrides


def cmd_run(args) -> int:
    cfg = load_config(getattr(args, "config", None), _overrides_from_args(args))
    if getattr(args, "model", None):
        shared = normalize_models({"shared": args.model}).get("shared") or []
        if shared:
            cfg.models.pop("default", None)
            for role in cfg.required_model_roles():
                cfg.models[role] = list(shared)

    if getattr(args, "print_config", False):
        print(json.dumps({
            "target": cfg.target, "scope": cfg.scope, "out_dir": cfg.out_dir, "backend": cfg.backend,
            "models": cfg.models, "model_concurrency": cfg.model_concurrency,
            "concurrency": cfg.concurrency, "lenses": cfg.lenses,
            "threat_model": cfg.threat_model, "finders_per_lens": cfg.finders_per_lens,
            "max_rounds": cfg.max_rounds, "dry_rounds": cfg.dry_rounds, "verify_votes": cfg.verify_votes,
            "enable_poc": cfg.enable_poc, "decompose": cfg.decompose, "resume": cfg.resume,
            "methods_dir": cfg.methods_abs, "methods_ok": cfg.methods_ok(),
            "model_config_error": cfg.model_config_error(),
            "backend_command": cfg.backend_spec().command,
            "health_check": {"enabled": cfg.health.enabled, "on_start": cfg.health.on_start,
                             "gate": cfg.health.gate, "ttl_s": cfg.health.ttl_s,
                             "all_models": cfg.all_models()},
        }, ensure_ascii=False, indent=2))
        return 0

    model_error = cfg.model_config_error()
    if model_error:
        print(f"⚠ 模型配置错误:{model_error}", file=sys.stderr)
        return 2

    # 惰性 import,避免 serve-only 环境缺依赖时报错
    from .events import EventBus
    from .pipeline import Pipeline

    store = RunStore(cfg.out_dir).ensure()
    bus = EventBus(sink=store.append_event)
    pipe = Pipeline(cfg, store=store, emitter=bus.emit)
    try:
        result = asyncio.run(pipe.run())
    except KeyboardInterrupt:
        print("\n⚠ 已中断。结构化态已保存,重跑相同命令可续跑(除非 --fresh)。", file=sys.stderr)
        return 130

    if getattr(args, "export", True):
        from . import exporters
        state = store.load_full_state()
        written = exporters.export_all(cfg.out_dir, state, pipe.meta_dict())
        print(f"已导出 {len(written)} 个文件到 {cfg.out_dir}/", file=sys.stderr)

    print("\n" + "=" * 60)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_serve(args) -> int:
    cfg = load_config(getattr(args, "config", None), _overrides_from_args(args))
    try:
        import uvicorn  # noqa
    except Exception:
        print("启动 Web 控制台需要 fastapi 与 uvicorn:\n  pip install fastapi 'uvicorn[standard]'", file=sys.stderr)
        return 1
    from .server import create_app
    app = create_app(cfg)
    print(f"proto-vuln-hunt Web 控制台:http://{cfg.host}:{cfg.port}  (runs 目录: {cfg.runs_dir})")
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        return cmd_serve(args)
    # run / 无子命令(旧式)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())

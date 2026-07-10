# proto-vuln-hunt (python)

`proto-vuln-hunt` workflow 的 **Python 移植版**:协议栈/管理面 C/C++ 白盒漏洞挖掘流水线
(攻击树威胁分析 → 攻击方式审计 → witness/blocker 对抗验证 → 流式产出确认漏洞 → 高危 PoC → 汇总),
但**每个 agent 通过外部后端执行**,且带一个 **Web 控制台**。你可以在**配置文件**里:

- 选择后端:`claude` / `opencode` / `codex`(也能自定义任意 CLI 的调用方式);
- 为不同阶段(role)配置**不同模型**,并限制**每个模型自己的并发数**;
- 设置**全局并发数**与全部流水线参数;
- **断点续跑**、后端任务失败重试。

**两种用法**:
- `serve` —— 启动 Web 控制台:浏览器里配置/启动/停止 run、**SSE 实时监控**、按严重度浏览漏洞、可视化覆盖图、导出。
- `run` —— 命令行跑一次(无人值守/CI 友好),结束后把 MD/SARIF 导出到 run 目录。

**结构化为主的产物模型**:运行期只写**结构化态**(`state.json`)并发**结构化事件**(`events.jsonl` + SSE);
Markdown / SARIF 由 `exporters.py` 从结构化态**按需渲染**(Web 导出端点 / CLI `--export`)。这样 Web 能严重度优先、
实时增量地呈现漏洞与覆盖,而文件产物随时可一键导出。

每次 agent 调用会记录 token 使用量到 `usage.jsonl` 并通过 Web 实时展示。Web「Agent」页签会按 agent
分角色分类展示后端实时输出,分类与单个 agent 输出窗口都可折叠,并可在 opencode JSON 事件流的可读视图与原始流之间切换,
用于观察当前执行。若后端没有返回真实 usage,
本工具用轻量算法估算:ASCII 约 4 字符/token,非 ASCII 约 1 字符/token。

---

## 安装

```bash
pip install -r requirements.txt          # CLI(run)仅需 PyYAML;Web 控制台(serve)另需 fastapi + uvicorn
# 只用 CLI、且用 JSON 配置 → 零依赖也能跑;只想跑 Web → pip install pyyaml fastapi 'uvicorn[standard]'
```

确保你要用的后端 CLI 已安装并完成登录鉴权:

| 后端 | 非交互调用 | 模型名格式 |
|---|---|---|
| `claude`   | `claude -p --output-format json ...`(提示词走 stdin) | `claude-opus-4-8` / `claude-sonnet-4-6` |
| `opencode` | `opencode serve`(长驻 server;每个 agent 新建 session) | `anthropic/claude-sonnet-4-6`、`openai/gpt-5` |
| `codex`    | `codex exec --model <m> <prompt>`                     | `gpt-5-codex` / `o3` |

> claude/codex 默认以"绕过审批/全自动"模式运行(`--dangerously-skip-permissions` /
> `--dangerously-bypass-approvals-and-sandbox`),因为这是无人值守流水线。请在**你授权审计的代码**上运行。

---

## 快速开始

### A. Web 控制台(推荐)

```bash
cp config.example.yaml my.yaml          # 选后端、配模型、设并发
python -m proto_vuln_hunt serve --config my.yaml --port 8000
# 打开 http://127.0.0.1:8000 → 「新建审计」填目标/后端/模型/lens/参数 → 启动
# 仪表盘:状态/轮次/严重度统计 + 威胁分析攻击树 + 漏洞(实时增量、可展开看 7 段报告)+ 覆盖图 + 历史问题 + 风险 + 活动日志 + 导出
```

各 run 落在 `--runs-dir`(默认 `./pvh-runs/<run_id>/`)。Web 支持多 run 并发、停止、续跑;关掉服务再开,历史 run 仍在列表里(SSE 从 `events.jsonl` 重放)。

### B. 命令行(无人值守 / CI)

```bash
# 跑一个仓(run 子命令)
python -m proto_vuln_hunt run --config my.yaml --target /path/to/repo

# 只审子目录/单文件
python -m proto_vuln_hunt run --config my.yaml --target /repo --scope src/proto/parser.c

# 换后端 / 统一模型 / 调并发(命令行覆盖配置)
python -m proto_vuln_hunt run --config my.yaml --target /repo --backend codex \
  --model gpt-5-codex,o3 --concurrency 6 --model-concurrency default=1,gpt-5-codex=2,o3=1

# 冒烟:小范围、单 finder、单轮、单票、关 PoC
python -m proto_vuln_hunt run --config my.yaml --target /repo --scope src/x.c \
  --lenses memory,integer --finders-per-lens 1 --max-rounds 1 --dry-rounds 1 --verify-votes 1 --no-poc

# 从已有 run 目录或 history.json 导入已分析好的历史问题模式;导入后跳过 git commit 分析
python -m proto_vuln_hunt run --config my.yaml --target /repo \
  --history-import-from ./pvh-runs/20260622-120000-abcd

# run 结束默认把 MD/SARIF 导出到 out_dir;--no-export 关闭。中断后重跑同命令自动续跑;--fresh 从头来;--print-config 看配置
```

---

## 配置文件

见 `config.example.yaml`(含详细注释)。要点:

```yaml
backend: claude                       # claude | opencode | codex
run_mode: full                        # 2.0 仅支持完整流程;保留字段用于 run 清单显示
# history_import_from: ./pvh-runs/<run_id>  # 可选:导入既有 run/history.json 的历史问题模式,跳过 git commit 分析

models:                               # 按 role 显式配模型;不支持 models.default 回落;列表会轮换使用
  threat:  claude-opus-4-8            # 常用 role: threat/history/recheck/audit/verify/report/poc
  history: claude-sonnet-4-6          # git 历史问题模式挖掘(每条提交一个 agent,与 high audit finder 同级调度)
  recheck: claude-sonnet-4-6
  audit:   [claude-sonnet-4-6, claude-opus-4-8]
  verify:  claude-sonnet-4-6
  report:  claude-sonnet-4-6
  poc:     claude-sonnet-4-6

concurrency: 4                        # 全局同时运行的 agent 上限
model_concurrency:                    # 单个模型自己的并发上限;未列出则默认等于全局 concurrency
  default: 1
  claude-sonnet-4-6: 2
  claude-opus-4-8: 1

model_time_windows:                   # 单个模型的可用时间段;未列出默认全天可用
  claude-opus-4-8: "00:00~06:00"      # 本地时间,左闭右开;跨零点可写 22:00~02:00
  claude-sonnet-4-6:
    - "00:00~06:00"
    - "22:00~24:00"

params:
  finders_per_lens: 2
  dry_rounds: 2
  max_rounds: 6
  verify_votes: 3
  threat_model: REMOTE                # REMOTE | LOCAL_UNPRIVILEGED | BOTH
  enable_poc: true                    # 总开关;还需要 poc_components 非空才执行
  poc_components:                     # 设为 [] 表示不做 PoC 验证,也不要求 models.poc
    - type: minimal_poc               # 内置组件:隔离 worktree 中做最小化 PoC 验证
      min_severity: high
  lenses: [memory, integer, race, injection, authn, crypto, dos, infoleak, resource-realtime]

methods_dir: proto_vuln_hunt/methods  # 默认即项目自带方法库,无需配置;可覆盖为自定义目录

backends:                             # (可选)自定义任意 CLI 的调用方式
  claude:
    command: ["claude","-p","--output-format","json","--model","{model}","--dangerously-skip-permissions"]
    prompt_mode: stdin                # stdin | arg | file | serve(opencode)
    parse: claude_json                # claude_json | text
  opencode:
    command: ["opencode","serve","--hostname","{hostname}","--port","{port}"]
    prompt_mode: serve
    parse: text
```

**模型配置**:每个会运行的 role 必须显式配置模型,不再从 `models.default` 回落。每个 role 可写字符串或列表。
字符串里也可以用逗号分隔多个模型,例如 `--model gpt-5-codex,o3` 会把同一组模型展开到当前会运行的所有 role,
或写 `audit: "anthropic/a,openai/b"`。同一 role 下的 agent 调用会按
`model_concurrency` 加权轮换模型,并由每个模型自己的 semaphore 强制限流。
`model_time_windows` 可限制某个模型只在指定本地时间段内参与调度;未配置的模型默认全天可用。

**自定义后端**:`command` 是 token 列表,运行时把 `{model}` 替换为当前角色模型、`{prompt}` 替换为提示词
(仅 `prompt_mode: arg` 时需要)、`{prompt_file}` 替换为提示词临时文件路径(仅 `prompt_mode: file` 时需要);
`stdin` 模式则把提示词从标准输入喂入。`prompt_mode: serve` 为 opencode 专用,会启动一个长驻
`opencode serve` 并为每个 agent 创建新 session。`parse` 决定如何从 stdout 取回 agent 文本
(`claude_json` 取 JSON 的 `.result`,`text` 直接用 stdout)。

---

## 产物(结构化为主)

每个 run 是一个目录(Web:`pvh-runs/<run_id>/`;CLI:`<target>/.proto-vuln-hunt/`)。按**数据生命周期**分文件,而不是塞进一个大文件:

```
<run_dir>/
├── run.json             # 清单:配置快照 + 状态(running/done/stopped/...) + 汇总统计
├── checkpoint.json      # 运行时机制态(round/seq/processed/pending/dedup…),高频小幅刷
├── history.json         # git 历史安全修复提炼出的历史问题模式
├── threat-analysis/
│   ├── raw.json         # 威胁分析 agent 原始结构化输出
│   ├── graph.json       # SecAnt 内部攻击树图(资产/风险/goal/domain/surface/method)
│   └── warnings.json    # 规范化告警
├── attack-surface.json  # 攻击面(初始+动态)+ 覆盖台账 + progress,每轮整体快照(状态持续演变)
├── findings/<id>.json   # 每条确认漏洞一个文件(确认即写;含全文/votes/poc,人工反馈可追加更新)
├── events.jsonl         # append-only 事件日志(SSE 重放 / 服务重启回看)
└── exports/             # 按需渲染的 MD/SARIF(Web「导出全部」或 CLI --export 时生成)
```

**拆分判据**:会演变的(攻击树/覆盖)用单文件快照;漏洞用多文件、各自独立寻址、确认即流式落盘;运行机制态单独放 `checkpoint.json`,这样高频刷新不再带着漏洞全文反复重写。即时风险种子只进入 recheck 队列当场消费,不再单独存档。

**导出**(从结构化态按需渲染):`THREAT-ANALYSIS.md` / `ATTACK-SURFACE.md`(含覆盖台账)/
`findings/<CLASS>-NNN.md`(frontmatter + 7 段式)/ `INDEX.md` / `REPORT.sarif`(2.1.0)。
Web 端可逐条下载或一键导出全部;CLI `run` 默认导出到 out_dir(`--no-export` 关闭)。

REST/SSE 接口(`serve` 时):`/api/runs`(GET/POST)、`/api/runs/{id}`、`/stop`、`/resume`、
`/findings`、`/findings/{fid}`、`/coverage`、`/risks`、`/threat-analysis`、`/history`、`/health`(GET 各模型健康)、
`/health/check`(POST 触发复检)、`/events`(SSE,含 `agent_update` 实时 stdout/stderr 事件)、
`/export/{sarif,index.md,finding/{fid}.md,all}`。

---

## 工作流程(对齐原 workflow)

1. **Threat Analysis + History** — 健康检查后启动基于攻击树的威胁分析(role=`threat`):识别关键资产/风险,生成 `goal → domain → surface → method` 攻击树,并为每个 surface 定位代码路径;history 遍历 `git log`,每条提交派 1 个 agent(role=`history`)判定是否安全修复。
2. **Unified Scheduler** — 威胁分析输出的每个 `surface × method` 会变成一个 `attack_method` 审计项;history commit 分析从启动起就在统一优先级队列里,与 high audit finder 同级;recheck 最高优先级;候选验证/报告流水线高于普通审计。相同优先级按入队时间 FIFO。若队首任务所需模型容量不可用,调度器会扫描后续任务并先启动有可用模型的任务,避免模型空闲。
3. **History Feedback** — history 提炼出的「历史问题模式」随挖随补,回灌 Web「历史问题」页签与 recheck 同类变体排查队列。
4. **Audit** — 工作队列 loop-until-dry:每个攻击树叶子 method × lens × N finder;动态回灌新攻击面;每个审计项完成即存断点。
5. **Verify** — 逐发现运行 witness/blocker 交叉验证:正方构造合法触发 witness,反方构造 blocker/不可满足证明,两个裁判分别质询 witness 与 blocker,终局裁判做定向补查并输出 confirmed/rejected/suppressed_unproven/needs_manual_review。
6. **Report** — 每条存活漏洞立即生成 7 段式正文,作为结构化记录进 state + 发 `finding_confirmed` 事件(SSE 流式呈现)。
7. **PoC**(可选) — 由 `poc_components` 插拔式组件驱动;内置 `minimal_poc` 组件会在隔离 git worktree 副本里做最小化 PoC 验证(非 git/编不动则降级静态 PoC)。没有 PoC 组件时跳过该阶段。
7. **Synthesis** — 去重 + 写汇总到 `run.json`/`state.json` + 发 `run_done`(MD/SARIF 留待导出时渲染)。

---

## 健壮性

- **模型健康检查**:运行开始前对**所有配置的模型**各发一个短探针,确认每个模型可达且能正常回答,并记录首 token 延迟与平均 token 输出速度;之后真正用某模型派任务前,若其健康状态未知/异常/陈旧(超过 `ttl_s`)会自动补检一次(按 ttl 去重,不会每次都探)。健康度(状态/首 token/输出速度/探针答复/成功调用数/失败数)在 Web「模型」页**实时**呈现,可手动「重新检查」。探针不计入 token 用量。配置见 `config.example.yaml` 的 `health_check:` 块(可关闭)。
- **并发门**:`asyncio.Semaphore`,任意时刻 ≤ `concurrency` 个后端任务在跑。
- **后端任务失败重试**:opencode/claude/codex 内部已自行重试瞬时 API 抖动;本层只在 **后端任务整体失败**(非零退出 / 超时 / 输出无法解析为所需结构化 JSON)时重试——指数退避(`retry.backoff_*`,疑似限流时自动延长)。`retry.max_attempts` 是单组最多重试次数;threat 会不限组数一直重试到拿到结构化结果或用户停止,audit/recheck 单组耗尽后把该审计项放回队尾稍后继续重试。
- **单 agent 失败隔离**:任一后端任务异常/未产出结构化结果只影响该 agent/审计项,不拖垮整体;audit/recheck 会回队重试。
- **断点续跑**:威胁分析后/每轮/收尾各存结构化状态;在途候选(`pendingFindings`)整块持久化,续跑重注入,synthesis 再按 `file:line:bug_class` 去重。Web 重启时把"清单写着 running 但已无任务"的 run 标记为 `interrupted`,可一键续跑。
- **实时事件**:`Pipeline` 经 `EventBus` 发结构化事件 → 同步落 `events.jsonl` + 广播给 SSE 订阅者;前端用 `EventSource`(断线自动带 `Last-Event-ID` 续传)。

## 已知边界

- 结构化输出靠"要求 agent 输出 ```json 块 + 本地解析",而非引擎级强约束;解析失败按后端任务失败策略重试,threat 不再因有限次数失败直接使用兜底攻击面。
- PoC 的 worktree 隔离依赖目标是 git 仓;否则在主仓目录跑(以静态 PoC 为主)。
- 并发等同本工具同时派发的后端任务数;真实并发还受后端服务端限流约束。
- Web 控制台默认绑 `127.0.0.1`、无鉴权(本地单机工具)。对外暴露请自行加反代/鉴权。
- 前端用内置的小型 Markdown 渲染器(无 CDN/构建);只覆盖标题/列表/表格/代码/粗体/链接的常用子集。
```

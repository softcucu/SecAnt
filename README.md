# proto-vuln-hunt (python)

`proto-vuln-hunt` workflow 的 **Python 移植版**:同样的协议栈/管理面 C/C++ 白盒漏洞挖掘流水线
(侦察 → 区域拆解 → loop-until-dry 审计 → 多票对抗验证 → 流式产出确认漏洞 → 高危 PoC → 汇总),
但**每个 agent 通过外部 CLI 执行**,且带一个 **Web 控制台**。你可以在**配置文件**里:

- 选择后端:`claude` / `opencode` / `codex`(也能自定义任意 CLI 的调用方式);
- 为不同阶段(role)配置**不同模型**,并限制**每个模型自己的并发数**;
- 设置**全局并发数**与全部流水线参数;
- **断点续跑**、CLI 任务失败重试。

**两种用法**:
- `serve` —— 启动 Web 控制台:浏览器里配置/启动/停止 run、**SSE 实时监控**、按严重度浏览漏洞、可视化覆盖图、导出。
- `run` —— 命令行跑一次(无人值守/CI 友好),结束后把 MD/SARIF 导出到 run 目录。

**结构化为主的产物模型**:运行期只写**结构化态**(`state.json`)并发**结构化事件**(`events.jsonl` + SSE);
Markdown / SARIF 由 `exporters.py` 从结构化态**按需渲染**(Web 导出端点 / CLI `--export`)。这样 Web 能严重度优先、
实时增量地呈现漏洞与覆盖,而文件产物随时可一键导出。

每次 agent 调用会记录 token 使用量到 `usage.jsonl` 并通过 Web 实时展示。若后端 CLI 没有返回真实 usage,
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
| `opencode` | `opencode run --model provider/model <prompt_file 指令>` | `anthropic/claude-sonnet-4-6`、`openai/gpt-5` |
| `codex`    | `codex exec --model <m> <prompt>`                     | `gpt-5-codex` / `o3` |

> 三种后端默认都以"绕过审批/全自动"模式运行(`--dangerously-skip-permissions` /
> `--dangerously-bypass-approvals-and-sandbox`),因为这是无人值守流水线。请在**你授权审计的代码**上运行。

---

## 快速开始

### A. Web 控制台(推荐)

```bash
cp config.example.yaml my.yaml          # 选后端、配模型、设并发
python -m proto_vuln_hunt serve --config my.yaml --port 8000
# 打开 http://127.0.0.1:8000 → 「新建审计」填目标/后端/模型/lens/参数 → 启动
# 仪表盘:状态/轮次/严重度统计 + 漏洞(实时增量、可展开看 7 段报告)+ 覆盖图 + 风险 + 侦察 + 活动日志 + 导出
```

各 run 落在 `--runs-dir`(默认 `./pvh-runs/<run_id>/`)。Web 支持多 run 并发、停止、续跑;关掉服务再开,历史 run 仍在列表里(SSE 从 `events.jsonl` 重放)。

### B. 命令行(无人值守 / CI)

```bash
# 跑一个仓(run 子命令;不带子命令而带 --target 时也按 run 处理,向后兼容)
python -m proto_vuln_hunt run --config my.yaml --target /path/to/repo

# 只审子目录/单文件
python -m proto_vuln_hunt run --config my.yaml --target /repo --scope src/proto/parser.c

# 换后端 / 统一模型 / 调并发(命令行覆盖配置)
python -m proto_vuln_hunt run --config my.yaml --target /repo --backend codex \
  --model gpt-5-codex,o3 --concurrency 6 --model-concurrency default=1,gpt-5-codex=2,o3=1

# 冒烟:小范围、单 finder、单轮、单票、关 PoC
python -m proto_vuln_hunt run --config my.yaml --target /repo --scope src/x.c \
  --lenses memory,integer --finders-per-lens 1 --max-rounds 1 --dry-rounds 1 --verify-votes 1 --no-poc

# run 结束默认把 MD/SARIF 导出到 out_dir;--no-export 关闭。中断后重跑同命令自动续跑;--fresh 从头来;--print-config 看配置
```

---

## 配置文件

见 `config.example.yaml`(含详细注释)。要点:

```yaml
backend: claude                       # claude | opencode | codex

models:                               # 按 role 配模型,缺省回落到 default;列表会轮换使用
  default: claude-sonnet-4-6
  recon:   claude-opus-4-8            # role: recon/decompose/audit/verify/report/poc/synthesis/util
  audit:   [claude-sonnet-4-6, claude-opus-4-8]
  verify:  claude-sonnet-4-6

concurrency: 4                        # 全局同时运行的 agent 上限
model_concurrency:                    # 单个模型自己的并发上限;未列出则默认等于全局 concurrency
  default: 1
  claude-sonnet-4-6: 2
  claude-opus-4-8: 1

params:
  finders_per_lens: 2
  dry_rounds: 2
  max_rounds: 6
  verify_votes: 3
  threat_model: REMOTE                # REMOTE | LOCAL_UNPRIVILEGED | BOTH
  enable_poc: true
  lenses: [memory, integer, race, injection, authn, crypto, dos, infoleak]
  decompose: true

methods_dir: proto_vuln_hunt/methods  # 默认即项目自带方法库,无需配置;可覆盖为自定义目录

backends:                             # (可选)自定义任意 CLI 的调用方式
  claude:
    command: ["claude","-p","--output-format","json","--model","{model}","--dangerously-skip-permissions"]
    prompt_mode: stdin                # stdin | arg | file
    parse: claude_json                # claude_json | text
  opencode:
    command: ["opencode","run","--model","{model}","请读取并执行这个审计任务文件:{prompt_file}。不要输出思考过程,最终只输出一个合法 JSON 对象。"]
    prompt_mode: file
    parse: text
```

**模型配置**:每个 role 可写字符串或列表。字符串里也可以用逗号分隔多个模型,例如
`--model gpt-5-codex,o3` 或 `audit: "anthropic/a,openai/b"`。同一 role 下的 agent 调用会按
`model_concurrency` 加权轮换模型,并由每个模型自己的 semaphore 强制限流。

**自定义后端**:`command` 是 token 列表,运行时把 `{model}` 替换为当前角色模型、`{prompt}` 替换为提示词
(仅 `prompt_mode: arg` 时需要)、`{prompt_file}` 替换为提示词临时文件路径(仅 `prompt_mode: file` 时需要);
`stdin` 模式则把提示词从标准输入喂入。`parse` 决定如何从 stdout 取回 agent 文本(`claude_json` 取 JSON
的 `.result`,`text` 直接用 stdout)。opencode 默认使用 `file` 模式,避免长提示词作为命令行参数时被截断。

可用下面的本地脚本验证 opencode 风格调用不会把多行长提示词塞进 argv,同时验证每个模型的并发上限:

```bash
python3 -B scripts/test_opencode_prompt_file.py
```

---

## 产物(结构化为主)

每个 run 是一个目录(Web:`pvh-runs/<run_id>/`;CLI:`<target>/.proto-vuln-hunt/`)。按**数据生命周期**分文件,而不是塞进一个大文件:

```
<run_dir>/
├── run.json             # 清单:配置快照 + 状态(running/done/stopped/...) + 汇总统计
├── checkpoint.json      # 运行时机制态(round/seq/processed/pending/dedup…),高频小幅刷
├── recon.json           # 纯静态侦察认知(用途/威胁/仓库知识/build_hint/初始攻击面/历史模式),写一次
├── attack-surface.json  # 攻击面(初始+动态)+ 覆盖台账 + progress,每轮整体快照(状态持续演变)
├── findings/<id>.json   # 每条确认漏洞一个文件(确认即写、写一次即终态;含全文/votes/poc)
├── risks/<id>.json      # 每条风险一个文件(登记即写、写一次即终态)
├── events.jsonl         # append-only 事件日志(SSE 重放 / 服务重启回看)
└── exports/             # 按需渲染的 MD/SARIF(Web「导出全部」或 CLI --export 时生成)
```

**拆分判据**:会演变的(攻击面/覆盖)用单文件快照;写定不动的(漏洞/风险)用多文件、各自独立寻址、确认即流式落盘;纯认知(recon)单文件;运行机制态单独放 `checkpoint.json`,这样高频刷新不再带着漏洞全文反复重写。旧版单一 `state.json` 仍可被向后兼容读取。

**导出**(从结构化态按需渲染,内容与原 workflow 一致):`RECON.md` / `ATTACK-SURFACE.md`(含覆盖台账)/
`RISKS.md` / `findings/<CLASS>-NNN.md`(frontmatter + 7 段式)/ `INDEX.md` / `REPORT.sarif`(2.1.0)。
Web 端可逐条下载或一键导出全部;CLI `run` 默认导出到 out_dir(`--no-export` 关闭)。

REST/SSE 接口(`serve` 时):`/api/runs`(GET/POST)、`/api/runs/{id}`、`/stop`、`/resume`、
`/findings`、`/findings/{fid}`、`/coverage`、`/risks`、`/recon`、`/events`(SSE)、`/export/{sarif,index.md,finding/{fid}.md,all}`。

---

## 工作流程(对齐原 workflow)

1. **Recon** — 读仓库知识/历史问题 → 攻击面地图 + 历史模式(变体排查种子)+ build_hint(或从断点恢复)。
2. **Decompose** — 把每个大 region 拆成有界子任务(每个 agent 代码量可控)。
3. **Audit** — 工作队列 loop-until-dry:每攻击面 × lens × N finder;动态回灌新攻击面;每轮存断点。
4. **Verify** — 逐发现 `verify_votes` 票多视角对抗反驳,多数否决即杀。
5. **Report** — 每条存活漏洞立即生成 7 段式正文,作为结构化记录进 state + 发 `finding_confirmed` 事件(SSE 流式呈现)。
6. **PoC**(可选) — 高危项在隔离 git worktree 副本里尝试最小化编译触发(非 git/编不动则降级静态 PoC)。
7. **Synthesis** — 去重 + 写汇总到 `run.json`/`state.json` + 发 `run_done`(MD/SARIF 留待导出时渲染)。

---

## 健壮性

- **并发门**:`asyncio.Semaphore`,任意时刻 ≤ `concurrency` 个 CLI 子进程在跑。
- **CLI 任务失败重试**:opencode/claude/codex 内部已自行重试瞬时 API 抖动;本层只在 **CLI 任务整体失败**(子进程非零退出 / 超时 / 输出无法解析为所需结构化 JSON)时重试——指数退避(`retry.backoff_*`,疑似限流时自动延长)、最多 `retry.max_attempts` 次,耗尽后跳过该 agent(漏洞靠在途候选 + 续跑挽回)。
- **单 agent 失败隔离**:任一子进程异常/未产出结构化结果只跳过该条,不拖垮整体。
- **断点续跑**:侦察后/每轮/收尾各存 `state.json`;在途候选(`pendingFindings`)整块持久化,续跑重注入,synthesis 再按 `file:line:bug_class` 去重。Web 重启时把"清单写着 running 但已无任务"的 run 标记为 `interrupted`,可一键续跑。
- **实时事件**:`Pipeline` 经 `EventBus` 发结构化事件 → 同步落 `events.jsonl` + 广播给 SSE 订阅者;前端用 `EventSource`(断线自动带 `Last-Event-ID` 续传)。

## 已知边界

- 结构化输出靠"要求 agent 输出 ```json 块 + 本地解析",而非引擎级强约束;解析失败按 CLI 任务失败有限重试。
- PoC 的 worktree 隔离依赖目标是 git 仓;否则在主仓目录跑(以静态 PoC 为主)。
- 并发等同你机器能开的子进程数;真实并发还受后端服务端限流约束。
- Web 控制台默认绑 `127.0.0.1`、无鉴权(本地单机工具)。对外暴露请自行加反代/鉴权。
- 前端用内置的小型 Markdown 渲染器(无 CDN/构建);只覆盖标题/列表/表格/代码/粗体/链接的常用子集。
```

"""提示词构造器:从 proto-vuln-hunt 原 workflow 移植。

唯一实质改动:原 workflow 用 StructuredOutput 工具强制结构化输出;这里改为在提示词末尾
要求 agent 输出**单个 ```json 代码块**(由 backends.extract_json 解析),其余措辞尽量保持一致。
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List


OUTPUT_LANGUAGE_ZH = (
    "【语言要求】除 JSON 字段名、schema 枚举值、代码/命令/路径/函数名/报错原文等必须原样保留的内容外,"
    "最终输出中的所有自然语言必须使用中文;不要用英文写标题、摘要、描述、理由、报告正文或 Markdown 小节名。"
)


def must_struct(schema: Dict[str, Any]) -> str:
    """结构化收尾要求 + 内联 schema。"""
    return (
        "\n\n【必须遵守】完成分析后,**必须只输出一个 ```json 代码块**作为最终结果,"
        "其内容是符合下面 JSON Schema 的对象;不要在代码块之外再写解释,也不要输出多个 JSON 块。"
        "如果没有发现任何条目,也要返回(数组字段为空数组的)合法结构。\n"
        f"{OUTPUT_LANGUAGE_ZH}\n"
        "JSON Schema:\n```json\n" + json.dumps(schema, ensure_ascii=False) + "\n```"
    )


# ──────────────────────────── Lens 启发式(内联兜底) ────────────────────────────
LENS: Dict[str, Dict[str, str]] = {
    "memory": {"name": "内存破坏", "heuristics": (
        "堆/栈溢出:memcpy/memmove/strcpy/strcat/sprintf/snprintf 的长度或目标缓冲外部可控、off-by-one、栈数组下标越界;\n"
        "UAF/double-free:错误路径提前 free、释放后仍用、悬垂回调/链表节点、引用计数配对错误;\n"
        "OOB 读写:数组/指针算术越界、负偏移、flexible array member 尾随数据未校验长度;\n"
        "未初始化内存使用导致信息泄露。")},
    "integer": {"name": "整型溢出/类型混淆", "heuristics": (
        "算术溢出→欠分配/越界:a*b、len+1、size+hdr 溢出后做 malloc/memcpy;\n"
        "有符号/无符号混用与截断:int 存长度后转 size_t、(short)len、负长度当无符号用;\n"
        "网络字节序:ntohl/ntohs/be32toh 后未做上下界校验即用作长度/偏移/索引;\n"
        "长度字段→分配/拷贝链路全程未夹紧;\n"
        "类型混淆:union/void*/tag 字段不可信即按某型解释、container_of 误用、强制转换丢弃约束。")},
    "race": {"name": "竞态/TOCTOU", "heuristics": (
        "TOCTOU:检查(access/stat/lookup)与使用(open/写)之间状态可被改;\n"
        "缺锁共享态:多线程/信号/回调并发读写同一结构而无锁或锁粒度错;\n"
        "double-fetch:对同一不可信输入读两次,两次值可不一致;\n"
        "信号处理重入与非异步安全调用;连接半关闭/断开期间的悬垂状态与重入。")},
    "injection": {"name": "注入/反序列化", "heuristics": (
        "命令注入:system/popen/exec* 拼接含外部数据;\n"
        "路径穿越/符号链接:../、绝对路径、未规范化、follow symlink;\n"
        "格式化字符串:printf 族格式串含外部数据;\n"
        "反序列化:长度/计数/偏移/指针/类型标签直接信任,解析时未校验边界与自洽性,嵌套深度无限。")},
    "authn": {"name": "认证降级/绕过(设计层)", "heuristics": (
        "空凭证/默认凭证/调试后门被接受;\n"
        "非常量时间比较密码/HMAC/token(时序侧信道);\n"
        "认证回退/降级路径:可被诱导退回到弱认证或无认证;协商时未强制最小安全级;\n"
        "状态机混淆:未认证态即处理本应认证后才允许的报文/操作;认证步骤可跳过或乱序;\n"
        "会话/令牌/nonce 可预测或可重放;权限检查缺失或在错误的层做。")},
    "crypto": {"name": "密码算法误用(设计层)", "heuristics": (
        "弱/过时算法:MD5/SHA1 做签名、DES/RC4/ECB、可被降级协商到弱套件;\n"
        "分组模式误用:ECB、固定/可预测 IV、nonce 重用(尤其 GCM/CTR);\n"
        "完整性缺失:仅加密不认证(无 MAC)、MAC-then-encrypt 误序、可被篡改;\n"
        "证书/主机名校验被关闭或可绕过、信任任意 CA、不校验链/有效期/吊销;\n"
        "随机数源弱(rand()/时间种子)用于密钥/IV/nonce/会话;密钥硬编码或日志泄露。")},
    "dos": {"name": "DoS(含协议设计/空口 DoS)", "heuristics": (
        "空口/未认证单包即可崩溃或挂死服务(畸形长度/标志/类型字段触发 panic、断言、解引用空指针、除零);\n"
        "无界递归/无界分配/放大攻击(小输入触发大资源消耗);\n"
        "解析复杂度炸弹(嵌套/重复字段导致 O(n^2)+);\n"
        "状态/连接/内存耗尽:无上限的会话表、缓冲、定时器;\n"
        "死锁/活锁;while(len--) 在 len 为 0/负时下溢成超长循环;协议状态机被诱导进入卡死/重传风暴。")},
    "infoleak": {"name": "信息泄露", "heuristics": (
        "未初始化内存外泄:栈/堆缓冲或结构体未清零即整体回传(memcpy/copy_to_user/put_user/send/write 整个 struct);\n"
        "结构体 padding 泄露:对齐填充字节未清零随整块拷贝外发(逐字段赋值后整体外传);\n"
        "越界读回传(heartbleed 式):回读/回显长度取自不可信字段且大于实际写入,带出相邻内存;\n"
        "缓冲区复用残留:复用的发送/响应缓冲未按本次长度清空,带出上次内容;\n"
        "地址/指针泄露削弱 ASLR:把指针/栈地址/内核地址经日志、错误消息、响应字段、%p 泄出;\n"
        "敏感数据外泄:密钥/口令/token/会话/内部路径进日志、错误信息、调试/诊断接口、崩溃转储;\n"
        "预言式泄露:错误码/返回长度/响应时间差异构成 oracle(口令/HMAC 非常量时间比较见 crypto)。")},
    "resource-realtime": {"name": "嵌入式资源/实时性", "heuristics": (
        "固定资源池耗尽:连接表、会话表、重组缓冲、mbuf/sk_buff、消息块、DMA descriptor、timer、fd/handle 无上限占用或错误路径不归还;\n"
        "任务/消息队列堆积:输入可持续 enqueue 但消费者受限、队列满策略错误、丢包/背压缺失、重传风暴放大队列压力;\n"
        "watchdog/心跳/保活失效:攻击者可让主循环、协议任务或喂狗路径长时间阻塞,触发复位或服务离线;\n"
        "RTOS/task 栈与实时预算:递归、深调用链、大栈对象、长临界区、阻塞 IO/锁等待导致任务栈溢出、deadline miss 或优先级反转;\n"
        "中断/回调上下文误用:ISR/timer/callback 中做耗时解析、内存分配、锁等待、日志/IO,或与主任务共享资源造成饥饿/抖动。")},
}

PROTO_EXTRA = (
    "协议栈专项必查:长度/类型/标志字段未校验即读写;TLV/分片重组的偏移与长度重叠或超界;\n"
    "ntohl 后未夹紧;未认证态报文处理路径;重传/重组/重排序中的状态混淆。"
)

FINDER_ANGLES = [
    "正向数据流:从不可信输入入口出发,顺着数据流跟到危险操作,沿途找缺失的校验/长度夹紧/状态检查。",
    "反向汇聚:从危险原语(memcpy/分配/解引用/拷贝/格式化/锁/比较等)出发,反向回溯其参数是否最终来自攻击者且未被约束。",
    "全量清点:用 grep 种子把本 lens 的候选站点在范围内尽量全量列出,再逐一核实(广度优先,重在不漏)。",
    "边界与错误路径:聚焦边界条件(0/负/最大长度/空)、错误与异常处理路径、资源清理与释放路径上的缺陷。",
]

VERIFY_LENSES = [
    "可达性:从真实入口能否构造出到达此处的输入?中途有无 return/校验拦截?",
    "可控性:触发所需的值/长度/状态/顺序,攻击者能否真正控制?上游是否已夹紧?",
    "影响:这是 OOB 写 / 信息泄露 / 认证绕过 / RCE 还是仅 DoS?严重度是否名副其实?",
    "前置条件:是否需要难以满足的特权/竞态窗口/特殊配置才能触发?",
    "既有缓解:是否已有断言/长度检查/编译期约束/sanitizer 使其无害?",
]


class PromptBuilder:
    """持有运行级常量(目标/威胁模型/方法库等),产出各阶段提示词。"""

    def __init__(self, cfg):
        self.cfg = cfg
        self.target = cfg.target
        self.scope_note = f"(仅审子路径:{cfg.scope})" if cfg.scope else ""
        self.threat = cfg.threat_model
        self.methods_ok = cfg.methods_ok()
        self.methods_dir = cfg.methods_abs
        root = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
        self.attack_tree_skill = os.path.join(root, "attack-tree-threat-analysis.md")
        self.attack_method_catalog = os.path.join(root, "attack-method-reference-catalog.md")

    # ── 方法库接入 ──
    def methods_instruction(self, lens_key: str, is_proto: bool = True) -> str:
        if not self.methods_ok:
            return ""
        files = [f"{self.methods_dir}/00-methodology.md", f"{self.methods_dir}/lens-{lens_key}.md"]
        if is_proto:
            files.append(f"{self.methods_dir}/protocol-stack.md")
        bullet = "\n".join(f"  - {f}" for f in files)
        return (
            "**先用 Read 读以下方法文件并严格遵循其方法(权威,优先级高于下方速览)**:\n"
            f"{bullet}\n"
            "按其中的 **Phase A 清点 → Phase B 逐站点验证、coverage 纪律(每个模式 filed 或 cleared)、"
            "回合预算(够了就收尾,别无限深挖)** 执行。\n\n"
        )

    def verify_methods(self) -> str:
        if not self.methods_ok:
            return ""
        return (
            f"**先 Read 方法文件以统一判准**:{self.methods_dir}/00-severity-rubric.md"
            f"(FP 分类 + 威胁模型化严重度表 + 调整项)、{self.methods_dir}/00-methodology.md"
            "(第六节\"拒绝的偷懒否决理由\")。\n"
        )

    @staticmethod
    def finder_angle(idx: int) -> str:
        return FINDER_ANGLES[idx % len(FINDER_ANGLES)]

    @staticmethod
    def lens_block(lens_key: str) -> str:
        l = LENS[lens_key]
        return f"【lens:{lens_key} {l['name']}】聚焦以下并只报这一类(速览;完整方法见方法文件):\n{l['heuristics']}"

    def file_partition(self, item: Dict[str, Any], idx: int) -> str:
        fl: List[str] = item.get("files") or []
        n = self.cfg.finders_per_lens
        if n <= 1 or len(fl) <= 1:
            return ""
        mine = [f for i, f in enumerate(fl) if i % n == idx % n]
        if not mine:
            return ""
        return f"\n本 finder **优先覆盖这些文件**(其余文件由同 lens 的其它并行 finder 负责,避免重叠):{', '.join(mine)}"

    # ── 攻击树威胁分析 ──
    def threat_analysis(self, schema) -> str:
        skill_note = ""
        if os.path.isfile(self.attack_tree_skill):
            skill_note = (
                "本阶段必须先 Read 并遵循以下攻击树威胁分析 Skill:\n"
                f"- {self.attack_tree_skill}\n"
            )
            if os.path.isfile(self.attack_method_catalog):
                skill_note += f"其中 method 选择参考库:\n- {self.attack_method_catalog}\n"
        return (
            f"你在 SecAnt 流水线的**第一阶段:基于攻击树的威胁分析**。目标目录:{self.target}{self.scope_note}"
            f"(威胁模型:{self.threat})。\n"
            f"{skill_note}\n"
            "目标:基于源代码和可选产品文档,识别关键资产、关键风险,并按固定四层攻击树建模:"
            "goal → domain → surface → method;同时为每个 surface 定位真实存在的模块级代码路径。\n\n"
            "严格边界:\n"
            "- 这是理论威胁分析和后续审计范围设计,不是漏洞审计,不要输出已确认漏洞。\n"
            "- 关键资产不是攻击树节点;关键风险对应攻击目标 goal。\n"
            "- method 是针对 surface 的理论攻击方式,必须写 preconditions,不要机械罗列无关方法。\n"
            "- code_path_mappings 只绑定 surface,路径必须通过目录浏览/文件检索/代码内容确认真实存在;无法确认则 code_paths=[]。\n\n"
            "执行建议:\n"
            "1. 先读 README/docs/目录结构/主要入口,理解产品能力和部署形态。\n"
            "2. 识别关键资产及关键风险,风险名称描述损害结果,不要写攻击技术名。\n"
            "3. 为每个关键风险建立一棵攻击树,保持 goal→domain→surface→method 层级。\n"
            "4. 结合代码结构为每个 surface 定位模块级代码路径。\n"
            "5. 输出完整结构化结果。不要只把结果写入 res.json;最终回答必须是 JSON 代码块,由 SecAnt 接收并规范化为内部攻击树图。"
            + must_struct(schema)
        )

    # ── git 历史:单条提交的「是否安全修复 + 问题模式」判定(每条提交一个 agent) ──
    def history_commit(self, commit: Dict[str, Any], schema) -> str:
        h = commit.get("hash") or ""
        subj = commit.get("subject") or "(无标题)"
        return (
            f"你在对一份 C/C++ 源码树做白盒漏洞挖掘的**历史问题模式挖掘**子任务——只分析**一条 git 提交**。"
            f"目标目录:{self.target}{self.scope_note}(威胁模型:{self.threat})\n"
            f"待分析提交:`{h}`　标题:{subj}\n\n"
            "步骤:\n"
            f"(1) 用 `git show --stat {h}` 与 `git show {h}`(必要时 `git log -1 {h}`)读这条提交的**完整改动(diff)与说明**。\n"
            "(2) 判断它是否是一次**安全修复**——即修复了内存破坏/整型溢出/越界读写/UAF/double-free/竞态/TOCTOU/注入/"
            "反序列化/认证绕过或降级/加密误用/DoS/信息泄露/嵌入式资源或实时性失效等**安全缺陷**;而非纯功能、重构、格式化、文档、构建/CI 改动。"
            "提交信息里的 fix/security/overflow/CVE/vuln/oob/leak/use-after-free 等是线索,但判定以**改动代码本身**为准。\n"
            "(3) 若相关(security_related=true):精读改动前后的代码,提炼一条**可复用于同类变体排查的问题模式**"
            "(pattern:根因 + 缺陷类型 + 触发条件的抽象描述,**不要只抄提交标题**),标注最相关的 lens_hint、涉及文件,"
            "并在 rationale 里简述改动要点与判定理由。后续会据此在全仓搜索同类代码模式。\n"
            "(4) 若不相关:security_related=false 即可,其它字段可留空。\n"
            "只输出这一条提交的判定结果。"
            + must_struct(schema)
        )

    # ── 审计 finder ──
    def audit(self, item: Dict[str, Any], lens_key: str, idx: int, schema) -> str:
        kind = item.get("kind")
        if kind == "attack_method":
            ctx_obj = item.get("attack_context") or {}
            code_paths = ctx_obj.get("code_paths") or []
            code_path_text = "; ".join(
                f"{p.get('path')}({p.get('description') or '无说明'})" for p in code_paths if p.get("path")
            )
            head = (
                f"攻击树审计项「{ctx_obj.get('surface') or item.get('name')} / "
                f"{ctx_obj.get('method') or item.get('objective')}」"
            )
            files = ", ".join(item.get("files") or [])
            ctx = (
                f"关键资产:{ctx_obj.get('asset_name') or '?'}({ctx_obj.get('asset_type') or 'unknown'}, "
                f"criticality={ctx_obj.get('criticality') or '?'})\n"
                f"关键风险:{ctx_obj.get('risk_name') or '?'}\n"
                f"攻击目标:{ctx_obj.get('attack_goal') or '?'}\n"
                f"攻击域:{ctx_obj.get('domain') or '?'}\n"
                f"攻击面:{ctx_obj.get('surface') or '?'}({ctx_obj.get('surface_type') or 'other'})\n"
                f"理论攻击方式:{ctx_obj.get('method') or item.get('name') or '?'}\n"
                f"攻击前置条件:{'; '.join(ctx_obj.get('preconditions') or []) or '(未识别明确前提)'}\n"
                f"攻击面代码路径:{code_path_text or '(威胁分析未定位到可信路径,需要自行从 surface 名称和代码结构定位)'}\n"
                "任务:围绕这个攻击树叶子 method,判断代码中是否存在可达、可控、能导致对应风险的真实漏洞。"
                "不要泛扫整个仓,优先覆盖威胁分析给出的代码路径;只有追踪 source→sink 时才跳读外部相关函数。"
            )
        elif kind == "task":
            head = f"审计子任务「{item.get('objective')}」(属攻击面区域:{item.get('region') or '?'})"
            files = ", ".join(item.get("files") or [])
            fns = ", ".join(item.get("functions") or [])
            ctx = (
                f"**范围仅限**:{('文件 ' + files) if files else '(见目标)'}{(' 的函数 ' + fns) if fns else ''}"
                f"{('(约 ' + str(item.get('est_lines')) + ' 行)') if item.get('est_lines') else ''}\n"
                f"不可信输入:{item.get('untrusted_input') or '见威胁分析'}　信任边界:{item.get('trust_boundary') or '(未注明)'}　"
                f"入口点:{', '.join(item.get('entry_points') or []) or '自行定位'}\n"
                "**严格限定**:只精读上述范围内的代码;**不要通读范围外的文件**,只在追溯 source→sink 时才跳读外部的相关函数;够了就收尾返回。"
            )
        elif kind == "region":
            head = f"攻击面区域「{item.get('name')}」({item.get('category')})"
            files = ", ".join(item.get("files") or [])
            ctx = (
                f"不可信输入:{item.get('untrusted_input') or '见威胁分析'}\n"
                f"信任边界:{item.get('trust_boundary') or '(未注明)'}\n"
                f"入口点:{', '.join(item.get('entry_points') or []) or '自行定位'}"
            )
        elif kind == "variant":
            head = f"**同类变体排查**:历史问题模式「{item.get('pattern')}」(出处:{item.get('source') or '?'})"
            files = ", ".join(item.get("files") or [])
            ctx = ("任务:理解该历史问题的根因后,在**全仓搜索同类代码模式**(可用 rg / semgrep / tree-sitter 脚本 / "
                   "CodeQL 免编译查询枚举全仓同类站点),逐一核实是否存在相同或相似缺陷。这是有的放矢的定向排查,不是盲扫。")
        else:  # surface
            head = f"**动态新增攻击面**「{item.get('name')}」"
            files = ", ".join(item.get("files") or [])
            ctx = f"为何可疑:{item.get('why')}"

        return (
            f"你在对 C/C++ 源码做白盒**定向人工审计**。目标:{self.target}{self.scope_note}(威胁模型:{self.threat})\n"
            f"审计对象:{head}\n"
            f"涉及文件:{files or '(自行定位)'}\n"
            f"{ctx}\n\n"
            f"{self.methods_instruction(lens_key, True)}{self.lens_block(lens_key)}\n\n"
            f"{PROTO_EXTRA}\n\n"
            "要求:\n"
            "- 用 Read/rg 看**真实代码**,回溯数据流,不要臆测。允许用 semgrep / tree-sitter 小脚本 / CodeQL(免编译)辅助定位同类站点,但判定真伪以人工精读为准。\n"
            "- 每条 finding 必须给出 source→sink 传播路径与可控性判断;命中历史模式则填 variant_of。\n"
            "- **宁缺毋滥**:没有可信外部输入路径、或已被上游夹紧的,不要报。\n"
            "- 若发现新的值得另派 agent 深挖的攻击面/可疑数据流,放进 new_surfaces。\n"
            "- **潜在风险登记**:本轮没坐实成漏洞、但值得人工另行核实的**线索**放进 risk_notes(area/note/可选 file/severity_hint),汇总进 RISKS.md,不要硬凑成 finding。"
            "**最典型、最该登记的一类**是「校验只在调用方、被调点本身不自洽」的跨调用点隐患:你在审 A 函数时发现 A 调 B,A 做了充分校验、这条路径没问题;"
            "但 B(或某个危险原语/共享 helper)的安全**依赖调用方传入已校验的参数**,而**全仓其它调用 B 的地方未必都做了等价校验**。"
            "此时登记为风险点,note 写明:B 的位置、B 安全所依赖的前提(invariant)、以及\"还有哪些调用方、是否都满足该前提\"这个待核实问题——这是变体排查的种子。"
            "其它如长度校验分散、错误路径未统一释放、缺乏深度限制等同理。\n"
            "- **聚焦、限时**:挑最相关的约 8~12 个函数/代码段精读即可,不要遍历整个大仓;够了就收尾返回。\n"
            f"- **本 finder 的独特调查角度(#{idx + 1},与同 lens 的其它并行 finder 互补,不要重复别人的角度)**:{self.finder_angle(idx)}{self.file_partition(item, idx)}\n"
            "(只查这一个 lens;其他 lens 与未覆盖代码由别的 agent / 后续轮次覆盖。)"
            + must_struct(schema)
        )

    # ── 风险点复查(专用优先排查角色) ──
    def recheck_risk(self, item: Dict[str, Any], schema) -> str:
        return (
            f"你在对 C/C++ 源码做白盒**定向人工审计**。目标:{self.target}{self.scope_note}(威胁模型:{self.threat})\n"
            f"审计对象:**潜在风险点复查**「{item.get('area')}」\n"
            f"相关文件:{item.get('file') or '(自行定位)'}\n"
            f"风险说明:{item.get('note')}\n\n"
            "这条风险点的典型形态是「校验只在调用方、被调点本身不自洽」——某个被调函数 / 危险原语 / 共享 helper(记为 B)的安全"
            "**依赖调用方传入已校验的参数**,B 自身并不重新校验;已知某条调用路径(调用方做了充分校验)是安全的,"
            "但**全仓其它调用 B 的地方未必都做了等价校验**。\n"
            "请据风险说明先定位 B,然后:\n"
            "- 用 rg / semgrep / tree-sitter 脚本 / CodeQL(免编译)把**全仓所有调用 B 的站点**枚举出来(广度优先,别漏);\n"
            "- 逐一精读每个调用点:核实 B 保持安全所依赖的前提 / 不变量(长度已夹紧、指针非空、已认证等)在该调用点是否真的成立;\n"
            "- 对**不满足前提**的调用点,回溯 source→sink 并判可控性 / 可达性;坐实为漏洞的报成 finding;\n"
            "- **正面对照(必填)**:坐实的 finding 里,从你枚举到的调用点中挑**一处对同一 B 把校验做对了**的站点,"
            "填进该 finding 的 `good_validation_ref`(path:line + 一句话:它正确地校验/夹紧了什么不变量),"
            "用来对比说明本漏洞点缺了哪一步;\n"
            "- 仍可疑但未坐实的继续放进 risk_notes(写清新的待核实点);新的可疑数据流 / 入口放进 new_surfaces。\n"
            f"{PROTO_EXTRA}\n\n"
            "要求:看真实代码、回溯数据流,不要臆测;**宁缺毋滥**——没有可信外部输入路径、或已被上游夹紧的不要报。\n"
            "(这是有的放矢的定向变体排查,不是全仓盲扫。)"
            + must_struct(schema)
        )

    @staticmethod
    def _finding_brief(f: Dict[str, Any]) -> str:
        return (
            f"- 标题:{f.get('title')}\n"
            f"- 类型:{f.get('bug_class')}\n"
            f"- 位置:{f.get('file')}:{f.get('line') or '?'} 函数 {f.get('function')}\n"
            f"- 描述:{f.get('description')}\n"
            f"- 声称的 source→sink:{f.get('source_to_sink') or '(未给出)'}\n"
            f"- 变体来源:{f.get('variant_of') or '(无)'}\n"
        )

    @staticmethod
    def _proof_obligation(f: Dict[str, Any]) -> str:
        bc = (f.get("bug_class") or f.get("lens") or "").lower()
        if any(x in bc for x in ["integer", "overflow", "trunc", "signed"]):
            return (
                "整数类证明义务:不要把“可控”当成“可溢出”。必须同时核对协议/字段宽度/配置上限、"
                "代码 guard、运算位宽/有符号语义、溢出/截断条件是否可满足,并给出合法 witness 或不可满足证明。"
            )
        if any(x in bc for x in ["memory", "oob", "uaf", "buffer", "heap", "stack"]):
            return (
                "内存类证明义务:必须证明合法输入能让访问范围超出对象边界,或对象生命周期进入释放后使用/重复释放状态;"
                "只看到 memcpy/数组访问/free 不足以确认。"
            )
        if any(x in bc for x in ["auth", "state", "bypass", "credential"]):
            return (
                "认证/状态机类证明义务:必须证明未授权或错误状态能到达 protected action,且没有统一 auth/state gate 支配该路径。"
            )
        if any(x in bc for x in ["inject", "path", "format", "command", "symlink"]):
            return (
                "注入/路径类证明义务:必须证明 payload 穿过 normalization/filter 后仍进入解释器语义边界或逃出 base dir;"
                "字符串靠近 sink 不足以确认。"
            )
        if any(x in bc for x in ["race", "toctou", "double-fetch", "concurr"]):
            return (
                "竞态类证明义务:必须给出可行 interleaving,并证明锁/引用/事务没有覆盖 check-use 或共享状态访问区间。"
            )
        if any(x in bc for x in ["crypto", "cipher", "cert", "nonce", "random", "iv"]):
            return (
                "密码类证明义务:必须先证明该 primitive 承担安全属性,再证明攻击者能力可破坏该属性;"
                "坏味道或弱算法名本身不足以确认。"
            )
        if any(x in bc for x in ["dos", "resource", "exhaust", "deadlock", "watchdog"]):
            return (
                "DoS/资源类证明义务:必须证明低成本输入可重复导致资源超过配额/预算,影响服务整体可用性,而非单请求失败。"
            )
        if any(x in bc for x in ["leak", "disclosure", "uninit", "padding"]):
            return (
                "信息泄露类证明义务:必须证明敏感/未初始化/OOB 数据进入攻击者可见输出通道,且长度/权限允许观察。"
            )
        return (
            "通用证明义务:在攻击者能力、输入合法域、程序状态、代码约束的交集下,必须存在可触发坏结果的 witness。"
        )

    # ── Witness / blocker 对抗性验证:正方构造合法触发 witness ──
    def verify_witness(self, f: Dict[str, Any], schema) -> str:
        return (
            f"你是漏洞验证的**正方 witness builder**。当前威胁模型:{self.threat}。\n"
            "目标不是泛泛同意 finding,而是构造一个合法触发 witness:攻击者能力 ∩ 输入合法域 ∩ 程序状态 ∩ 代码约束 下,"
            "是否存在可触发坏结果的点。构造不出来就 witness_complete=false。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            f"专项证明义务:{self._proof_obligation(f)}\n\n"
            "请用 Read/rg 看真实代码,只追踪关键路径。若 witness_complete=true,必须同时给出:\n"
            "- witness:最小合法输入/状态/顺序/关键值;\n"
            "- attack_preconditions、input_domain_constraints、state_constraints、code_constraints;\n"
            "- path_nodes:入口到 sink/坏结果的 path:line 节点;\n"
            "- trigger_condition:合法 witness 如何满足坏条件;\n"
            "- sink_ref 与 bad_result;\n"
            "- evidence_refs、corrected_severity、exploitability。\n"
            "若任一关键约束没闭合,不要硬判真,把缺口写进 missing_evidence。"
            + must_struct(schema)
        )

    # ── Witness / blocker 对抗性验证:反方构造 blocker / 不可满足证明 ──
    def verify_blocker(self, f: Dict[str, Any], witness: Dict[str, Any], schema) -> str:
        witness_s = json.dumps(witness or {}, ensure_ascii=False)
        return (
            f"你是漏洞验证的**反方 blocker builder**。当前威胁模型:{self.threat}。\n"
            "目标不是泛泛说它像误报,而是构造 decisive blocker 或不可满足证明:证明所有合法 witness 都被约束排除,"
            "或所有相关路径都被 guard/state gate 阻断。找不到决定性 blocker 就 blocker_found=false。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            f"专项证明义务:{self._proof_obligation(f)}\n\n"
            f"正方 witness JSON(可攻击它的合法性,但不要只攻击一个局部 witness 后直接全局否决):\n```json\n{witness_s}\n```\n"
            "请用 Read/rg 看真实代码,重点找:\n"
            "- 输入域/协议/配置/类型宽度让坏条件不可满足;\n"
            "- guard/clamp/auth/state/lock/refcount 是否支配所有到 sink 的路径;\n"
            "- sink 语义是否并不危险,或影响/输出通道不成立。\n"
            "必须标注 blocker_scope:global/path_local/branch_local/config_local/partial/unknown/none。"
            "只有覆盖所有相关合法输入或所有相关路径时才写 global。"
            + must_struct(schema)
        )

    # ── Witness / blocker 对抗性验证:质询 witness ──
    def verify_witness_judge(self, f: Dict[str, Any], witness: Dict[str, Any],
                             blocker: Dict[str, Any], schema) -> str:
        witness_s = json.dumps(witness or {}, ensure_ascii=False)
        blocker_s = json.dumps(blocker or {}, ensure_ascii=False)
        return (
            f"你是漏洞验证的**witness 裁判**。当前威胁模型:{self.threat}。\n"
            "只质询正方 witness:它是否真的满足攻击者能力、输入合法域、程序状态、代码约束,并触发坏结果。"
            "不要重新做大范围审计,只核对会影响 witness 成立的 1-3 个关键事实。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            f"专项证明义务:{self._proof_obligation(f)}\n"
            f"正方 witness JSON:\n```json\n{witness_s}\n```\n"
            f"反方 blocker JSON(供参考):\n```json\n{blocker_s}\n```\n"
            "输出 witness_verdict:\n"
            "- accepted: witness 合法且关键约束闭合;\n"
            "- weakened: witness 基本可行但有非致命缺口;\n"
            "- rejected: witness 违反关键约束或无法触发坏结果;\n"
            "- inconclusive:证据不足。\n"
            "所有采用/反驳的事实都写进 evidence_refs 或 failed_checks。"
            + must_struct(schema)
        )

    # ── Witness / blocker 对抗性验证:质询 blocker ──
    def verify_blocker_judge(self, f: Dict[str, Any], witness: Dict[str, Any],
                             blocker: Dict[str, Any], schema) -> str:
        witness_s = json.dumps(witness or {}, ensure_ascii=False)
        blocker_s = json.dumps(blocker or {}, ensure_ascii=False)
        return (
            f"你是漏洞验证的**blocker 裁判**。当前威胁模型:{self.threat}。\n"
            "只质询反方 blocker:它是否全局/决定性,还是只打掉某条路径、某个分支、某个配置或某个局部 witness。"
            "不要重新做大范围审计,只核对支配关系、作用域和不可满足证明的关键事实。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            f"专项证明义务:{self._proof_obligation(f)}\n"
            f"正方 witness JSON:\n```json\n{witness_s}\n```\n"
            f"反方 blocker JSON:\n```json\n{blocker_s}\n```\n"
            "输出 blocker_verdict:\n"
            "- global_decisive: blocker 覆盖所有相关合法输入或所有到 sink 路径,可以否决;\n"
            "- partial: blocker 只覆盖局部路径/分支/配置/witness;\n"
            "- invalid: blocker 被代码证据推翻;\n"
            "- unknown_scope:作用域无法核实。\n"
            "声称 global_decisive 时必须给 evidence_refs 和 reviewed_checks。"
            + must_struct(schema)
        )

    # ── Witness / blocker 对抗性验证:终局裁判 + 定向补查 ──
    def verify_final_adjudicator(self, f: Dict[str, Any], witness: Dict[str, Any],
                                 blocker: Dict[str, Any], witness_review: Dict[str, Any],
                                 blocker_review: Dict[str, Any], schema) -> str:
        payload = json.dumps({
            "witness": witness or {},
            "blocker": blocker or {},
            "witness_review": witness_review or {},
            "blocker_review": blocker_review or {},
        }, ensure_ascii=False)
        return (
            f"你是漏洞验证的**终局裁判 + 定向补查员**。当前威胁模型:{self.threat}。\n"
            "你不是重新审计整仓。你的任务是读取正反和两个裁判结果,找出最影响最终决策的 1-2 个缺口,"
            "用 Read/rg 做限时补查,然后必须输出一个 operational_decision。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            f"专项证明义务:{self._proof_obligation(f)}\n"
            f"前四阶段 JSON:\n```json\n{payload}\n```\n"
            "决策口径:\n"
            "- confirmed: witness 被基本验证,且没有 verified global blocker;\n"
            "- rejected: blocker 被验证为 global/decisive,或坏条件在合法输入/状态/代码约束下不可满足;\n"
            "- suppressed_unproven: witness 不完整,blocker 也不决定性,证据不足以确认或否决;系统会作为编码质量问题保留到漏洞页;\n"
            "- needs_manual_review: high/critical 潜在影响且证据冲突,补查后仍无法闭合。\n"
            "同时输出 epistemic_verdict(proven_real/proven_false/unresolved)。不要用 unknown 作为 operational_decision。"
            + must_struct(schema)
        )

    # ── 对抗性验证:正方举证 ──
    def verify_prover(self, f: Dict[str, Any], schema) -> str:
        return (
            f"你是漏洞验证的**正方举证 agent**。当前威胁模型:{self.threat}。\n"
            "目标不是泛泛同意 finding,而是用真实代码证据证明它成立;证明不了就 supports_real=false。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            "请用 Read/rg 看真实代码,只追踪关键路径。若要 supports_real=true,必须同时给出:\n"
            "- 不可信输入入口(path:line)与攻击者可控字段/长度/状态;\n"
            "- 到漏洞点的 source_chain,每个节点写 path:line + 一句话;\n"
            "- sink_ref(path:line)与缺失/不足的校验;\n"
            "- reachability、controllability、corrected_severity、exploitability。\n"
            "如果入口不清、链路断裂、sink 不明确或关键代码没读到,不要硬判真,把缺口写进 missing_evidence。"
            + must_struct(schema)
        )

    # ── 对抗性验证:反方证伪 ──
    def verify_disprover(self, f: Dict[str, Any], schema) -> str:
        return (
            f"你是漏洞验证的**反方证伪 agent**。当前威胁模型:{self.threat}。\n"
            "默认这条 finding 是误报,但只有拿到真实代码证据才能 refutes_real=true。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            "用 Read/rg 看真实代码,回溯从不可信输入源到此处的完整路径。\n"
            "**判误报必须拿证据**(不得凭\"看起来不可达/有缓解/太难利用/别处校验过/只崩溃\"随手否决):"
            "只有当你能 caller-trace **证伪可达性**、或**确证上游校验确实把输入夹紧**、或**确证根本不是 bug**时,"
            "才 refutes_real=true。\n"
            "若 refutes_real=true,必须填写 clearing_checks 与 non_issue_reason,每条证据写 path:line + 一句话。"
            "反驳不掉时 refutes_real=false,把仍缺的证伪证据写进 missing_evidence。"
            + must_struct(schema)
        )

    # ── 对抗性验证:裁决 ──
    def verify_judge(self, f: Dict[str, Any], proof: Dict[str, Any],
                     disproof: Dict[str, Any], lens: str, schema) -> str:
        proof_s = json.dumps(proof or {}, ensure_ascii=False)
        disproof_s = json.dumps(disproof or {}, ensure_ascii=False)
        return (
            f"你是漏洞验证的**裁判 agent**。当前威胁模型:{self.threat}。裁决重点:{lens}\n\n"
            "你只裁决正反双方已经给出的结构化证据是否足够;不要重新做大范围审计。"
            "可以用 Read/rg 核对双方引用的少量 path:line,但不能凭直觉补齐缺失证据。\n\n"
            f"{self.verify_methods()}Finding:\n{self._finding_brief(f)}\n"
            f"正方举证 JSON:\n```json\n{proof_s}\n```\n"
            f"反方证伪 JSON:\n```json\n{disproof_s}\n```\n"
            "裁决规则:\n"
            "- decision=confirm:正方有完整 source_chain + sink_ref + evidence_refs,且反方没有给出能证伪的 clearing_checks;\n"
            "- decision=reject:反方有明确 clearing_checks + non_issue_reason,能证伪可达性/可控性/bug 成立性;\n"
            "- decision=inconclusive:任一关键证据缺失、双方证据冲突但无法判定、或引用无法核实。\n"
            "输出 decision=confirm 时 is_real=true;decision=reject 时 is_real=false;inconclusive 时 is_real=false,"
            "但必须在 missing_evidence 写清缺口。所有采用的证据都必须进入 evidence_refs。"
            + must_struct(schema)
        )

    # ── PoC ──
    def poc(self, rec: Dict[str, Any], build_hint: str, schema) -> str:
        return (
            "你要为一条已确认的 C/C++ 漏洞构造**验证级 PoC**。你处于一个**隔离的工作目录副本**(改动不影响主仓,可自由编译)。\n"
            "目标根目录就是当前工作目录。漏洞:\n"
            f"- 标题:{rec.get('title')} ({rec.get('bug_class')}, 严重度 {rec.get('corrected_severity')})\n"
            f"- 位置:{rec.get('file')}:{rec.get('line') or '?'} 函数 {rec.get('function')}\n"
            f"- source→sink:{rec.get('source_to_sink') or '(见描述)'}\n"
            f"- 描述:{rec.get('description')}\n"
            f"- 编译提示 build_hint:{build_hint or '(无,自行探测 Makefile/CMake)'}\n\n"
            "步骤:\n"
            "1. 从攻击入口反向构造到漏洞点的**最小调用链**,写一个尽量小的 harness/触发用例(harness_code)。\n"
            "2. **尝试最小化编译**(优先只编译相关源文件;可加 -fsanitize=address,undefined)。给出 build_cmd。\n"
            "3. 能编译就运行触发用例,观察是否崩溃/sanitizer 报错/逻辑断言失败 → 填 compiled/triggered。\n"
            "4. **若无法编译**(依赖过重/构建复杂/缺工具),降级为**静态 PoC**:给出精确触发输入字节构造与代码级触发路径,compiled=false 并在 notes 写明降级原因。\n"
            "5. 给出可利用性评级(exploitability)。\n"
            "**限时**:编译/调试不要无限尝试,卡住就降级静态 PoC 并说明。"
            + must_struct(schema)
        )

    # ── 报告正文(返回纯 Markdown 正文,frontmatter 由 Python 拼接) ──
    @staticmethod
    def _votes_brief(rec: Dict[str, Any]) -> str:
        return json.dumps(
            [{"phase": v.get("phase"), "decision": v.get("decision"), "is_real": v.get("is_real"),
              "evidence_refs": v.get("evidence_refs"), "source_chain": v.get("source_chain"),
              "sink_ref": v.get("sink_ref"), "clearing_checks": v.get("clearing_checks"),
              "reachability": v.get("reachability"), "controllability": v.get("controllability"),
              "reasoning": v.get("reasoning"), "non_issue_reason": v.get("non_issue_reason")}
             for v in (rec.get("votes") or [])], ensure_ascii=False)

    @staticmethod
    def _poc_brief(poc: Any) -> str:
        return json.dumps({
            "compiled": poc.get("compiled"), "triggered": poc.get("triggered"),
            "approach": poc.get("approach"), "build_cmd": poc.get("build_cmd"),
            "exploitability": poc.get("exploitability"), "notes": poc.get("notes"),
            "harness_code": poc.get("harness_code"),
        }, ensure_ascii=False) if poc else "(未做动态 PoC,给出静态触发构造说明)"

    def report_body(self, rec: Dict[str, Any], poc: Any) -> str:
        votes_brief = self._votes_brief(rec)
        poc_brief = self._poc_brief(poc)
        # 按发现来源附加两类对照小节:历史问题排查命中 → 类似哪个历史问题;
        # 潜在风险点排查命中 → 哪一处其他代码把校验做对了(正面对照)。
        extras = ""
        variant_of = (rec.get("variant_of") or "").strip()
        if variant_of:
            extras += (
                f"⑩ **与历史问题的关联** —— 本漏洞由历史问题模式的同类变体排查命中,说明它**和哪个历史问题类似**"
                f"(历史问题模式 / 出处:{variant_of}):同样的根因 / 缺陷类型是什么、此处如何复现了同类缺陷;\n"
            )
        good_ref = (rec.get("good_validation_ref") or "").strip()
        if good_ref:
            extras += (
                f"⑪ **正面对照:其他调用点的正确校验** —— 本漏洞由潜在风险点排查命中,贴出**哪一处其他代码把校验做对了**"
                f"({good_ref}):它正确地校验 / 夹紧了哪个不变量,对比说明本漏洞点缺了这一步、应照其补齐;\n"
            )
        return (
            f"把下面这**一条**已确认漏洞写成中文 Markdown **正文**(不要写 YAML frontmatter,我会自己加)。\n"
            f"{OUTPUT_LANGUAGE_ZH}\n"
            f"目标仓:{self.target}{self.scope_note};漏洞位置 {rec.get('file')}:{rec.get('line') or '?'} 函数 {rec.get('function')}。\n\n"
            "正文按以下小节(与方法库 00-methodology.md 的 7 段式一致):\n"
            "① **漏洞描述** —— 为什么是漏洞:破坏了什么不变量、攻击者控制什么;\n"
            "② **相关代码** —— 用 Read 取真实代码片段贴出(够上下文让 bug 一目了然),不要转述;\n"
            "③ **数据流** —— 来源(不可信来源 path:line)/危险点(sink path:line)/校验(中途有无校验、为何不足);\n"
            "④ **可达性调用链** —— 从真实入口到 sink 的简短调用链;\n"
            f"⑤ **影响与可利用性**(威胁模型 {self.threat}):{rec.get('exploitability') or '见验证结论'};\n"
            "⑥ **已检查缓解** —— canary / ASLR / FORTIFY / sanitizer / 类型上界等是否存在、可否绕过;\n"
            f"⑦ **PoC / 验证结果**:{poc_brief};\n"
            f"⑧ **修复建议** —— 怎么修;⑨ 置信度={rec.get('confidence')}(说明依据)。\n"
            f"{extras}"
            f"对抗性验证结论(供你参考,提炼进报告):{votes_brief}\n"
            "**只输出报告正文 Markdown 本身**(从 ## ① 漏洞描述 之类开始),不要任何额外说明、不要代码块包裹整篇。"
        )

    # ── 汇总(INDEX.md 正文) ──
    def synthesis(self, *, counts, top_sev, final_findings, regions, repo_knowledge, history,
                  rounds, converged, stop_reason, candidates) -> str:
        idx_rows = json.dumps([{"id": c["id"], "severity": c["corrected_severity"], "bug_class": c["bug_class"],
                                "title": c["title"], "file": c["file"], "line": c.get("line", 0),
                                "report": f"findings/{c['id']}.md"} for c in final_findings], ensure_ascii=False)
        surf = json.dumps([{"name": r.get("name"), "category": r.get("category"),
                            "priority": r.get("priority"), "untrusted_input": r.get("untrusted_input")}
                           for r in (regions or [])], ensure_ascii=False)
        knowledge = json.dumps({"repo_knowledge": repo_knowledge or "",
                                "history": [h.get("pattern") for h in (history or [])]}, ensure_ascii=False)
        methods_note = f"已用({self.methods_dir})" if self.methods_ok else "不可用(用了内联兜底)"
        conv = "已收敛" if converged else f"未收敛 —— {stop_reason},可重跑(resume 默认开)续审"
        return (
            "请输出一篇中文 **INDEX.md 正文**(纯 Markdown,我会直接保存为 INDEX.md;不要写 frontmatter,不要用代码块包裹整篇),结构:\n"
            f"{OUTPUT_LANGUAGE_ZH}\n"
            f"① 摘要:目标 {self.target}{self.scope_note};威胁模型 {self.threat};方法库 {methods_note};"
            f"确认漏洞 {len(final_findings)} 条;候选去重池 {candidates};最高危等级 {top_sev};收敛情况:{conv};审计轮数 {rounds}。\n"
            f"② 按 bug_class 计数:{json.dumps(counts, ensure_ascii=False)}\n"
            f"③ 攻击面地图(精炼):{surf}\n"
            f"④ 仓库知识与历史模式提要:{knowledge}\n"
            f"⑤ 漏洞索引表(severity 从高到低,每行链接到 findings/<id>.md):{idx_rows}\n"
            "⑥ 建议的模糊测试桩(针对最高优先级的解析/收包入口,给出挂钩哪个函数、如何用 libFuzzer/AFL++ 插桩编译)。\n"
            "⑦ 下一步动态验证计划。\n"
            "直接输出 Markdown 正文。"
        )

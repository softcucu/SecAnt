"""proto-vuln-hunt (python):协议栈/管理面 C/C++ 安全漏洞挖掘流水线的 Python 移植版。

可通过配置文件选择后端 CLI(claude/opencode/codex)、为不同阶段配置不同模型、设置并发数。
"""
from .config import Config, load_config
from .pipeline import Pipeline

__all__ = ["Config", "load_config", "Pipeline"]
__version__ = "0.2.0"

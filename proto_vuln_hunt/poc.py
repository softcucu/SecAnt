"""Pluggable PoC component registry.

PoC verification is an optional post-confirmation phase. Components are small
adapters that decide whether they apply to a finding and then produce a result
object consumed by report generation.
"""
from __future__ import annotations

import importlib
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol

from . import schemas as S

MINIMAL_POC_TYPE = "minimal_poc"
_POC_TYPE_ALIASES = {"agent": MINIMAL_POC_TYPE, "harness": MINIMAL_POC_TYPE}
DEFAULT_POC_COMPONENTS = [{"type": MINIMAL_POC_TYPE}]


class PocComponent(Protocol):
    name: str
    component_type: str

    def required_roles(self) -> List[str]:
        ...

    def should_run(self, rec: Dict[str, Any]) -> bool:
        ...

    async def run(self, pipeline: Any, rec: Dict[str, Any]) -> Any:
        ...


PocFactory = Callable[[Mapping[str, Any]], PocComponent]
_POC_FACTORIES: Dict[str, PocFactory] = {}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _split_csv(raw: str) -> List[str]:
    return [x.strip() for x in raw.split(",") if x.strip()]


def normalize_poc_components(raw: Any) -> List[Dict[str, Any]]:
    """Normalize user config into a list of component specs.

    Supported forms:
      poc_components: ["minimal_poc", "pkg.module:Factory"]
      poc_components: [{type: minimal_poc, enabled: true}]
      poc: {components: [...]}  # handled by load_config before this helper
    """
    if raw is None:
        return [dict(x) for x in DEFAULT_POC_COMPONENTS]
    if raw is False:
        return []
    if isinstance(raw, str):
        return [{"type": _canonical_component_type(item)} for item in _split_csv(raw)]
    if isinstance(raw, Mapping):
        if "components" in raw:
            return normalize_poc_components(raw.get("components"))
        spec = dict(raw)
        spec.setdefault("type", spec.pop("kind", MINIMAL_POC_TYPE))
        spec["type"] = _canonical_component_type(spec.get("type"))
        return [spec]
    if isinstance(raw, (list, tuple)):
        out: List[Dict[str, Any]] = []
        for item in raw:
            if item is None or item is False:
                continue
            if isinstance(item, str):
                item = item.strip()
                if item:
                    out.append({"type": _canonical_component_type(item)})
            elif isinstance(item, Mapping):
                spec = dict(item)
                spec.setdefault("type", spec.pop("kind", MINIMAL_POC_TYPE))
                spec["type"] = _canonical_component_type(spec.get("type"))
                out.append(spec)
            else:
                out.append({"type": _canonical_component_type(item)})
        return [x for x in out if x.get("type")]
    key = _canonical_component_type(raw)
    return [{"type": key}] if key else []


def active_poc_component_specs(*, enable_poc: bool, components: Any) -> List[Dict[str, Any]]:
    if not enable_poc:
        return []
    specs = normalize_poc_components(components)
    return [dict(spec) for spec in specs if spec.get("enabled", True) is not False]


def register_poc_component(component_type: str, factory: PocFactory) -> None:
    key = str(component_type or "").strip()
    if not key:
        raise ValueError("PoC component type must not be empty")
    _POC_FACTORIES[key] = factory


def _canonical_component_type(component_type: Any) -> str:
    key = str(component_type or "").strip()
    return _POC_TYPE_ALIASES.get(key, key)


def _import_factory(path: str) -> PocFactory:
    if ":" in path:
        module_name, attr = path.split(":", 1)
    else:
        module_name, _, attr = path.rpartition(".")
    if not module_name or not attr:
        raise ValueError(f"未知 PoC 组件类型:{path}")
    obj = getattr(importlib.import_module(module_name), attr)
    if isinstance(obj, type):
        return obj  # type: ignore[return-value]
    if callable(obj):
        return obj  # type: ignore[return-value]
    raise ValueError(f"PoC 组件 {path} 不是可调用对象")


def _factory_for(component_type: str) -> PocFactory:
    key = _canonical_component_type(component_type)
    if key in _POC_FACTORIES:
        return _POC_FACTORIES[key]
    if ":" in key or "." in key:
        factory = _import_factory(key)
        _POC_FACTORIES[key] = factory
        return factory
    raise ValueError(f"未知 PoC 组件类型:{key}")


def build_poc_components(specs: Iterable[Mapping[str, Any]]) -> List[PocComponent]:
    components: List[PocComponent] = []
    for raw in specs:
        spec = dict(raw)
        if spec.get("enabled", True) is False:
            continue
        component_type = _canonical_component_type(spec.get("type") or spec.get("kind") or MINIMAL_POC_TYPE)
        factory = _factory_for(component_type)
        components.append(factory(spec))
    return components


def required_model_roles_for_poc_specs(specs: Iterable[Mapping[str, Any]]) -> List[str]:
    roles: List[str] = []
    for raw in specs:
        spec = dict(raw)
        if spec.get("enabled", True) is False:
            continue
        component_type = _canonical_component_type(spec.get("type") or spec.get("kind") or MINIMAL_POC_TYPE)
        if component_type == MinimalPocComponent.component_type:
            role = str(spec.get("role") or "poc").strip()
            if role and role not in roles:
                roles.append(role)
            continue
        try:
            component = _factory_for(component_type)(spec)
        except Exception:
            continue
        for role in component.required_roles():
            if role and role not in roles:
                roles.append(role)
    return roles


class BasePocComponent:
    component_type = "base"

    def __init__(self, spec: Optional[Mapping[str, Any]] = None):
        self.spec = dict(spec or {})
        self.name = str(self.spec.get("name") or self.spec.get("type") or self.component_type)

    def required_roles(self) -> List[str]:
        return []

    def _allowed_severities(self) -> List[str]:
        severities = self.spec.get("severities")
        if isinstance(severities, str):
            vals = _split_csv(severities)
        elif isinstance(severities, (list, tuple, set)):
            vals = [str(x).strip() for x in severities]
        else:
            min_sev = str(self.spec.get("min_severity") or "high").strip().lower()
            threshold = _SEVERITY_RANK.get(min_sev, _SEVERITY_RANK["high"])
            vals = [sev for sev, rank in _SEVERITY_RANK.items() if rank >= threshold]
        return [sev for sev in vals if sev in _SEVERITY_RANK]

    def should_run(self, rec: Dict[str, Any]) -> bool:
        severity = str(rec.get("corrected_severity") or rec.get("severity") or "").lower()
        return severity in set(self._allowed_severities())


class MinimalPocComponent(BasePocComponent):
    """Built-in component that asks the PoC role to build a minimal trigger PoC."""

    component_type = MINIMAL_POC_TYPE

    def required_roles(self) -> List[str]:
        return [str(self.spec.get("role") or "poc")]

    async def run(self, pipeline: Any, rec: Dict[str, Any]) -> Any:
        role = str(self.spec.get("role") or "poc")
        label = f"{self.name}:{rec['id']}"
        cwd = pipeline._ensure_poc_worktree()
        return await pipeline.runner.run(
            pipeline.pb.poc(rec, pipeline.build_hint, S.POC_SCHEMA),
            role=role,
            label=label,
            schema=S.POC_SCHEMA,
            cwd=cwd,
        )


register_poc_component(MinimalPocComponent.component_type, MinimalPocComponent)
register_poc_component("agent", MinimalPocComponent)    # backwards-compatible alias
register_poc_component("harness", MinimalPocComponent)  # backwards-compatible alias

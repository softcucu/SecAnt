"""Attack-tree threat analysis normalization.

The attack-tree skill describes a final ``res.json`` shape, but SecAnt keeps an
incremental graph as its internal model.  This module accepts a skill-shaped
object and turns it into a tolerant graph snapshot plus audit items.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple


ASSET_TYPES = {"service", "data", "credential", "privilege", "software", "configuration", "key", "device", "other"}
CRITICALITIES = {"critical", "high", "medium", "low"}
SECURITY_PROPERTIES = {"confidentiality", "integrity", "availability", "authenticity", "authorization", "accountability"}
NODE_TYPES = {"goal", "domain", "surface", "method"}
SURFACE_TYPES = {"protocol", "api", "interface", "service", "port", "file", "message", "configuration", "command", "package", "physical", "other"}


def _list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _text(v: Any) -> str:
    return str(v or "").strip()


def _safe_list_text(v: Any) -> List[str]:
    return [_text(x) for x in _list(v) if _text(x)]


def _next_id(prefix: str, n: int) -> str:
    return f"{prefix}-{n:03d}"


def _norm_key(*parts: Any) -> str:
    return "\x1f".join(" ".join(_text(p).lower().split()) for p in parts)


def _next_available_id(prefix: str, used: set) -> str:
    n = 1
    while True:
        value = _next_id(prefix, n)
        if value not in used:
            used.add(value)
            return value
        n += 1


def _merge_text_list(dst: Dict[str, Any], src: Dict[str, Any], key: str) -> None:
    seen = {_norm_key(x) for x in _safe_list_text(dst.get(key))}
    out = _safe_list_text(dst.get(key))
    for item in _safe_list_text(src.get(key)):
        nk = _norm_key(item)
        if nk and nk not in seen:
            seen.add(nk)
            out.append(item)
    dst[key] = out


def _unique_id(raw: Any, prefix: str, used: set, counter: List[int], warnings: List[str], what: str) -> str:
    value = _text(raw)
    if not value or value in used:
        if value in used:
            warnings.append(f"{what} id 重复: {value}; 已重新分配")
        counter[0] += 1
        value = _next_id(prefix, counter[0])
        while value in used:
            counter[0] += 1
            value = _next_id(prefix, counter[0])
    used.add(value)
    return value


def _priority_from_asset(asset: Dict[str, Any]) -> str:
    c = asset.get("criticality")
    if c == "critical":
        return "high"
    if c == "high":
        return "high"
    if c == "low":
        return "low"
    return "medium"


def _nodes_by_parent(nodes: Dict[str, Dict[str, Any]]) -> Dict[Optional[str], List[Dict[str, Any]]]:
    by_parent: Dict[Optional[str], List[Dict[str, Any]]] = {}
    for node in nodes.values():
        by_parent.setdefault(node.get("parent_id"), []).append(node)
    for arr in by_parent.values():
        arr.sort(key=lambda x: (int(x.get("order") or 0), x.get("name") or ""))
    return by_parent


def _ancestor(nodes: Dict[str, Dict[str, Any]], node: Dict[str, Any], node_type: str) -> Optional[Dict[str, Any]]:
    cur = node
    seen = set()
    while cur:
        if cur.get("node_type") == node_type:
            return cur
        pid = cur.get("parent_id")
        if not pid or pid in seen:
            return None
        seen.add(pid)
        cur = nodes.get(pid)
    return None


def normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return a tolerant threat graph snapshot from a skill-shaped object."""
    raw = _dict(raw)
    warnings: List[str] = []
    assets: List[Dict[str, Any]] = []
    trees: List[Dict[str, Any]] = []
    nodes: Dict[str, Dict[str, Any]] = {}
    mappings: Dict[str, Dict[str, Any]] = {}
    audit_items: List[Dict[str, Any]] = []

    asset_used: set = set()
    risk_used: set = set()
    tree_used: set = set()
    node_used: set = set()
    asset_counter = [0]
    risk_counter = [0]
    tree_counter = [0]
    node_counter = [0]
    asset_id_map: Dict[str, str] = {}
    risk_id_map: Dict[Tuple[str, str], str] = {}

    for a in _list(raw.get("assets")):
        ad = _dict(a)
        old_asset_id = _text(ad.get("asset_id"))
        asset_id = _unique_id(old_asset_id, "ASSET", asset_used, asset_counter, warnings, "asset")
        asset_id_map[old_asset_id or asset_id] = asset_id
        asset_type = _text(ad.get("asset_type")) or "other"
        if asset_type not in ASSET_TYPES:
            warnings.append(f"{asset_id} asset_type 非法: {asset_type}; 已改为 other")
            asset_type = "other"
        criticality = _text(ad.get("criticality")) or "medium"
        if criticality not in CRITICALITIES:
            warnings.append(f"{asset_id} criticality 非法: {criticality}; 已改为 medium")
            criticality = "medium"
        risks: List[Dict[str, Any]] = []
        for r in _list(ad.get("risks")):
            rd = _dict(r)
            old_risk_id = _text(rd.get("risk_id"))
            risk_id = _unique_id(old_risk_id, "RISK", risk_used, risk_counter, warnings, "risk")
            risk_id_map[(asset_id, old_risk_id or risk_id)] = risk_id
            prop = _text(rd.get("security_property")) or "availability"
            if prop not in SECURITY_PROPERTIES:
                warnings.append(f"{risk_id} security_property 非法: {prop}; 已改为 availability")
                prop = "availability"
            risks.append({
                "risk_id": risk_id,
                "name": _text(rd.get("name")) or "未命名关键风险",
                "security_property": prop,
                "description": _text(rd.get("description")),
            })
        assets.append({
            "asset_id": asset_id,
            "name": _text(ad.get("name")) or "未命名关键资产",
            "description": _text(ad.get("description")),
            "asset_type": asset_type,
            "criticality": criticality,
            "risks": risks,
            "status": "done",
        })

    asset_by_id = {a["asset_id"]: a for a in assets}

    for t in _list(raw.get("attack_trees")):
        td = _dict(t)
        tree_id = _unique_id(td.get("tree_id"), "TREE", tree_used, tree_counter, warnings, "tree")
        raw_asset_id = _text(td.get("asset_id"))
        asset_id = asset_id_map.get(raw_asset_id, raw_asset_id)
        if asset_id not in asset_by_id:
            warnings.append(f"{tree_id} 引用未知 asset_id={raw_asset_id}; 已使用第一个资产")
            asset_id = assets[0]["asset_id"] if assets else "ASSET-000"
        raw_risk_id = _text(td.get("risk_id"))
        risk_id = risk_id_map.get((asset_id, raw_risk_id), raw_risk_id)
        asset = asset_by_id.get(asset_id) or {}
        valid_risks = {r.get("risk_id") for r in _list(asset.get("risks"))}
        if risk_id not in valid_risks:
            warnings.append(f"{tree_id} 引用未知 risk_id={raw_risk_id}; 已使用该资产第一个风险")
            risk_id = next(iter(valid_risks), "RISK-000")

        tree_nodes: List[str] = []
        old_to_new_node: Dict[str, str] = {}
        pending_parent: Dict[str, Any] = {}
        for nd_raw in _list(td.get("nodes")):
            nd = _dict(nd_raw)
            old_node_id = _text(nd.get("node_id"))
            node_id = _unique_id(old_node_id, "NODE", node_used, node_counter, warnings, "node")
            old_to_new_node[old_node_id or node_id] = node_id
            ntype = _text(nd.get("node_type")) or "method"
            if ntype not in NODE_TYPES:
                warnings.append(f"{node_id} node_type 非法: {ntype}; 已改为 method")
                ntype = "method"
            surface_type = _text(nd.get("surface_type")) if ntype == "surface" else ""
            if ntype == "surface" and surface_type and surface_type not in SURFACE_TYPES:
                warnings.append(f"{node_id} surface_type 非法: {surface_type}; 已改为 other")
                surface_type = "other"
            node = {
                "node_id": node_id,
                "tree_id": tree_id,
                "asset_id": asset_id,
                "risk_id": risk_id,
                "parent_id": None,
                "node_type": ntype,
                "name": _text(nd.get("name")) or _text(td.get("attack_goal")) or "未命名节点",
                "order": int(nd.get("order") or 0),
                "basis": _safe_list_text(nd.get("basis")),
                "preconditions": _safe_list_text(nd.get("preconditions")) if ntype == "method" else [],
                "surface_type": surface_type if ntype == "surface" else "",
                "status": "done",
            }
            pending_parent[node_id] = nd.get("parent_id")
            nodes[node_id] = node
            tree_nodes.append(node_id)

        for node_id in tree_nodes:
            old_parent = _text(pending_parent.get(node_id))
            parent_id = old_to_new_node.get(old_parent, old_parent)
            if parent_id and parent_id in nodes:
                nodes[node_id]["parent_id"] = parent_id
            elif parent_id:
                warnings.append(f"{node_id} parent_id 引用未知: {old_parent}; 已置空")

        root_id = old_to_new_node.get(_text(td.get("root_node_id")), _text(td.get("root_node_id")))
        if not root_id or root_id not in nodes or nodes[root_id].get("node_type") != "goal":
            roots = [nid for nid in tree_nodes if nodes[nid].get("node_type") == "goal"]
            root_id = roots[0] if roots else (tree_nodes[0] if tree_nodes else "")
            if root_id:
                warnings.append(f"{tree_id} root_node_id 不合法; 已使用 {root_id}")
        trees.append({
            "tree_id": tree_id,
            "asset_id": asset_id,
            "risk_id": risk_id,
            "attack_goal": _text(td.get("attack_goal")) or (nodes.get(root_id, {}).get("name") or "未命名攻击目标"),
            "root_node_id": root_id,
            "node_ids": tree_nodes,
            "status": "done",
        })

    for mp in _list(raw.get("code_path_mappings")):
        md = _dict(mp)
        sid = _text(md.get("surface_node_id"))
        if sid not in nodes:
            warnings.append(f"code_path_mappings 引用未知 surface_node_id={sid}; 已跳过")
            continue
        code_paths = []
        for cp in _list(md.get("code_paths")):
            cpd = _dict(cp)
            path = _text(cpd.get("path"))
            if not path:
                continue
            code_paths.append({"path": path, "description": _text(cpd.get("description"))})
        mappings[sid] = {"surface_node_id": sid, "code_paths": code_paths, "status": "done"}

    by_parent = _nodes_by_parent(nodes)
    asset_lookup = {a["asset_id"]: a for a in assets}
    tree_lookup = {t["tree_id"]: t for t in trees}
    for node in nodes.values():
        node["children"] = [c["node_id"] for c in by_parent.get(node["node_id"], [])]

    for method in sorted((n for n in nodes.values() if n.get("node_type") == "method"),
                         key=lambda x: (x.get("tree_id") or "", int(x.get("order") or 0), x.get("name") or "")):
        surface = _ancestor(nodes, method, "surface") or {}
        domain = _ancestor(nodes, method, "domain") or {}
        goal = _ancestor(nodes, method, "goal") or {}
        tree = tree_lookup.get(method.get("tree_id")) or {}
        asset = asset_lookup.get(method.get("asset_id")) or {}
        mapping = mappings.get(surface.get("node_id") or "", {"code_paths": []})
        code_paths = mapping.get("code_paths") or []
        files = [cp["path"] for cp in code_paths if cp.get("path")]
        item_id = f"{method.get('tree_id')}:{surface.get('node_id')}:{method.get('node_id')}"
        method_name = method.get("name") or "未命名攻击方式"
        surface_name = surface.get("name") or "未命名攻击面"
        item = {
            "id": item_id,
            "kind": "attack_method",
            "name": method_name,
            "objective": f"{surface_name} / {method_name}",
            "priority": _priority_from_asset(asset),
            "files": files,
            "attack_context": {
                "asset_id": method.get("asset_id"),
                "asset_name": asset.get("name") or "",
                "asset_type": asset.get("asset_type") or "",
                "criticality": asset.get("criticality") or "",
                "risk_id": method.get("risk_id"),
                "risk_name": next((r.get("name") for r in _list(asset.get("risks")) if r.get("risk_id") == method.get("risk_id")), ""),
                "tree_id": method.get("tree_id"),
                "attack_goal": tree.get("attack_goal") or goal.get("name") or "",
                "goal_node_id": goal.get("node_id") or "",
                "domain_node_id": domain.get("node_id") or "",
                "domain": domain.get("name") or "",
                "surface_node_id": surface.get("node_id") or "",
                "surface": surface_name,
                "surface_type": surface.get("surface_type") or "",
                "method_node_id": method.get("node_id"),
                "method": method_name,
                "preconditions": method.get("preconditions") or [],
                "basis": {
                    "goal": goal.get("basis") or [],
                    "domain": domain.get("basis") or [],
                    "surface": surface.get("basis") or [],
                    "method": method.get("basis") or [],
                },
                "code_paths": code_paths,
            },
        }
        audit_items.append(item)

    return {
        "schema_version": "secant-threat-graph-1.0",
        "source_schema_version": _text(raw.get("schema_version")) or "",
        "analysis_id": _text(raw.get("analysis_id")) or "",
        "sources": _dict(raw.get("sources")),
        "assets": assets,
        "trees": trees,
        "nodes": list(nodes.values()),
        "code_path_mappings": list(mappings.values()),
        "audit_items": audit_items,
        "warnings": warnings,
        "stats": {
            "assets": len(assets),
            "trees": len(trees),
            "nodes": len(nodes),
            "surfaces": sum(1 for n in nodes.values() if n.get("node_type") == "surface"),
            "methods": sum(1 for n in nodes.values() if n.get("node_type") == "method"),
            "audit_items": len(audit_items),
        },
    }


def rebuild_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute children, audit_items, and stats for an internal threat graph."""
    graph = _dict(graph)
    assets = [_dict(a) for a in _list(graph.get("assets"))]
    trees = [_dict(t) for t in _list(graph.get("trees"))]
    node_arr = [_dict(n) for n in _list(graph.get("nodes"))]
    mappings_arr = [_dict(m) for m in _list(graph.get("code_path_mappings"))]
    nodes = {n.get("node_id"): n for n in node_arr if n.get("node_id")}
    for n in nodes.values():
        n["children"] = []
    by_parent = _nodes_by_parent(nodes)
    for node in nodes.values():
        node["children"] = [c["node_id"] for c in by_parent.get(node["node_id"], [])]

    mappings = {m.get("surface_node_id"): m for m in mappings_arr if m.get("surface_node_id")}
    asset_lookup = {a.get("asset_id"): a for a in assets if a.get("asset_id")}
    tree_lookup = {t.get("tree_id"): t for t in trees if t.get("tree_id")}
    audit_items: List[Dict[str, Any]] = []
    for method in sorted((n for n in nodes.values() if n.get("node_type") == "method"),
                         key=lambda x: (x.get("tree_id") or "", int(x.get("order") or 0), x.get("name") or "")):
        surface = _ancestor(nodes, method, "surface") or {}
        domain = _ancestor(nodes, method, "domain") or {}
        goal = _ancestor(nodes, method, "goal") or {}
        tree = tree_lookup.get(method.get("tree_id")) or {}
        asset = asset_lookup.get(method.get("asset_id")) or {}
        mapping = mappings.get(surface.get("node_id") or "", {"code_paths": []})
        code_paths = mapping.get("code_paths") or []
        files = [cp["path"] for cp in code_paths if cp.get("path")]
        item_id = f"{method.get('tree_id')}:{surface.get('node_id')}:{method.get('node_id')}"
        method_name = method.get("name") or "未命名攻击方式"
        surface_name = surface.get("name") or "未命名攻击面"
        audit_items.append({
            "id": item_id,
            "kind": "attack_method",
            "name": method_name,
            "objective": f"{surface_name} / {method_name}",
            "priority": _priority_from_asset(asset),
            "files": files,
            "attack_context": {
                "asset_id": method.get("asset_id"),
                "asset_name": asset.get("name") or "",
                "asset_type": asset.get("asset_type") or "",
                "criticality": asset.get("criticality") or "",
                "risk_id": method.get("risk_id"),
                "risk_name": next((r.get("name") for r in _list(asset.get("risks")) if r.get("risk_id") == method.get("risk_id")), ""),
                "tree_id": method.get("tree_id"),
                "attack_goal": tree.get("attack_goal") or goal.get("name") or "",
                "goal_node_id": goal.get("node_id") or "",
                "domain_node_id": domain.get("node_id") or "",
                "domain": domain.get("name") or "",
                "surface_node_id": surface.get("node_id") or "",
                "surface": surface_name,
                "surface_type": surface.get("surface_type") or "",
                "method_node_id": method.get("node_id"),
                "method": method_name,
                "preconditions": method.get("preconditions") or [],
                "basis": {
                    "goal": goal.get("basis") or [],
                    "domain": domain.get("basis") or [],
                    "surface": surface.get("basis") or [],
                    "method": method.get("basis") or [],
                },
                "code_paths": code_paths,
            },
        })

    graph["assets"] = assets
    graph["trees"] = trees
    graph["nodes"] = list(nodes.values())
    graph["code_path_mappings"] = mappings_arr
    graph["audit_items"] = audit_items
    warnings = _list(graph.get("warnings"))
    graph["warnings"] = warnings
    graph["stats"] = {
        "assets": len(assets),
        "trees": len(trees),
        "nodes": len(nodes),
        "surfaces": sum(1 for n in nodes.values() if n.get("node_type") == "surface"),
        "methods": sum(1 for n in nodes.values() if n.get("node_type") == "method"),
        "audit_items": len(audit_items),
    }
    return graph


def graph_summary(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Small stable summary for prompt-side duplicate avoidance."""
    graph = _dict(graph)
    return {
        "assets": [
            {
                "name": a.get("name"),
                "asset_type": a.get("asset_type"),
                "criticality": a.get("criticality"),
                "risks": [r.get("name") for r in _list(a.get("risks"))],
            }
            for a in _list(graph.get("assets"))
        ],
        "attack_items": [
            {
                "asset": (it.get("attack_context") or {}).get("asset_name"),
                "risk": (it.get("attack_context") or {}).get("risk_name"),
                "goal": (it.get("attack_context") or {}).get("attack_goal"),
                "domain": (it.get("attack_context") or {}).get("domain"),
                "surface": (it.get("attack_context") or {}).get("surface"),
                "method": (it.get("attack_context") or {}).get("method"),
            }
            for it in _list(graph.get("audit_items"))
        ],
    }


def merge_delta(base: Dict[str, Any], raw_delta: Dict[str, Any], *, origin: str = "dynamic") -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Merge threat-analysis delta into an existing graph with semantic de-duplication."""
    delta = normalize(raw_delta or {})
    if not _list(base.get("assets")) and not _list(base.get("nodes")):
        graph = rebuild_graph(delta)
        stats = graph.get("stats") or {}
        return graph, {
            "assets": int(stats.get("assets") or 0),
            "risks": sum(len(_list(a.get("risks"))) for a in _list(graph.get("assets"))),
            "trees": int(stats.get("trees") or 0),
            "nodes": int(stats.get("nodes") or 0),
            "surfaces": int(stats.get("surfaces") or 0),
            "methods": int(stats.get("methods") or 0),
            "code_paths": sum(len(_list(m.get("code_paths"))) for m in _list(graph.get("code_path_mappings"))),
        }

    graph = rebuild_graph(base)
    assets = _list(graph.get("assets"))
    trees = _list(graph.get("trees"))
    node_arr = _list(graph.get("nodes"))
    mappings_arr = _list(graph.get("code_path_mappings"))
    nodes = {n.get("node_id"): n for n in node_arr if isinstance(n, dict) and n.get("node_id")}
    mappings = {m.get("surface_node_id"): m for m in mappings_arr if isinstance(m, dict) and m.get("surface_node_id")}

    asset_used = {a.get("asset_id") for a in assets if isinstance(a, dict) and a.get("asset_id")}
    risk_used = {r.get("risk_id") for a in assets if isinstance(a, dict) for r in _list(a.get("risks")) if isinstance(r, dict) and r.get("risk_id")}
    tree_used = {t.get("tree_id") for t in trees if isinstance(t, dict) and t.get("tree_id")}
    node_used = {n.get("node_id") for n in node_arr if isinstance(n, dict) and n.get("node_id")}

    stats = {"assets": 0, "risks": 0, "trees": 0, "nodes": 0, "surfaces": 0, "methods": 0, "code_paths": 0}
    asset_by_key = {_norm_key(a.get("name"), a.get("asset_type")): a for a in assets if isinstance(a, dict)}
    asset_id_map: Dict[str, str] = {}
    risk_id_map: Dict[Tuple[str, str], str] = {}

    for da in _list(delta.get("assets")):
        if not isinstance(da, dict):
            continue
        akey = _norm_key(da.get("name"), da.get("asset_type"))
        asset = asset_by_key.get(akey)
        if not asset:
            asset = {
                "asset_id": _next_available_id("ASSET", asset_used),
                "name": da.get("name") or "未命名关键资产",
                "description": da.get("description") or "",
                "asset_type": da.get("asset_type") or "other",
                "criticality": da.get("criticality") or "medium",
                "risks": [],
                "status": "done",
                "origin": origin,
            }
            assets.append(asset)
            asset_by_key[akey] = asset
            stats["assets"] += 1
        elif not asset.get("description") and da.get("description"):
            asset["description"] = da.get("description")
        asset_id_map[da.get("asset_id")] = asset.get("asset_id")

        risk_by_key = {_norm_key(r.get("name"), r.get("security_property")): r for r in _list(asset.get("risks")) if isinstance(r, dict)}
        for dr in _list(da.get("risks")):
            if not isinstance(dr, dict):
                continue
            rkey = _norm_key(dr.get("name"), dr.get("security_property"))
            risk = risk_by_key.get(rkey)
            if not risk:
                risk = {
                    "risk_id": _next_available_id("RISK", risk_used),
                    "name": dr.get("name") or "未命名关键风险",
                    "security_property": dr.get("security_property") or "availability",
                    "description": dr.get("description") or "",
                    "origin": origin,
                }
                asset.setdefault("risks", []).append(risk)
                risk_by_key[rkey] = risk
                stats["risks"] += 1
            elif not risk.get("description") and dr.get("description"):
                risk["description"] = dr.get("description")
            risk_id_map[(asset.get("asset_id"), dr.get("risk_id"))] = risk.get("risk_id")

    tree_by_key = {_norm_key(t.get("asset_id"), t.get("risk_id"), t.get("attack_goal")): t for t in trees if isinstance(t, dict)}
    node_index = {
        (n.get("tree_id"), n.get("parent_id") or "", n.get("node_type"), _norm_key(n.get("name"))): n
        for n in nodes.values()
    }
    delta_nodes = {n.get("node_id"): n for n in _list(delta.get("nodes")) if isinstance(n, dict) and n.get("node_id")}
    node_id_map: Dict[str, str] = {}

    for dt in _list(delta.get("trees")):
        if not isinstance(dt, dict):
            continue
        asset_id = asset_id_map.get(dt.get("asset_id"), dt.get("asset_id"))
        risk_id = risk_id_map.get((asset_id, dt.get("risk_id")), dt.get("risk_id"))
        tkey = _norm_key(asset_id, risk_id, dt.get("attack_goal"))
        tree = tree_by_key.get(tkey)
        if not tree:
            tree = {
                "tree_id": _next_available_id("TREE", tree_used),
                "asset_id": asset_id,
                "risk_id": risk_id,
                "attack_goal": dt.get("attack_goal") or "未命名攻击目标",
                "root_node_id": "",
                "node_ids": [],
                "status": "done",
                "origin": origin,
            }
            trees.append(tree)
            tree_by_key[tkey] = tree
            stats["trees"] += 1

        pending = list(dt.get("node_ids") or [])
        while pending:
            progressed = False
            rest: List[str] = []
            for did in pending:
                dn = delta_nodes.get(did)
                if not dn:
                    continue
                dparent = dn.get("parent_id")
                if dparent and dparent not in node_id_map:
                    rest.append(did)
                    continue
                parent_id = node_id_map.get(dparent) if dparent else None
                nkey = (tree.get("tree_id"), parent_id or "", dn.get("node_type"), _norm_key(dn.get("name")))
                node = node_index.get(nkey)
                if not node:
                    node = copy.deepcopy(dn)
                    node["node_id"] = _next_available_id("NODE", node_used)
                    node["tree_id"] = tree.get("tree_id")
                    node["asset_id"] = asset_id
                    node["risk_id"] = risk_id
                    node["parent_id"] = parent_id
                    node["status"] = "done"
                    node["origin"] = origin
                    nodes[node["node_id"]] = node
                    node_index[nkey] = node
                    tree.setdefault("node_ids", []).append(node["node_id"])
                    stats["nodes"] += 1
                    if node.get("node_type") == "surface":
                        stats["surfaces"] += 1
                    if node.get("node_type") == "method":
                        stats["methods"] += 1
                else:
                    _merge_text_list(node, dn, "basis")
                    _merge_text_list(node, dn, "preconditions")
                    if node.get("node_id") not in tree.setdefault("node_ids", []):
                        tree["node_ids"].append(node.get("node_id"))
                node_id_map[did] = node.get("node_id")
                if node.get("node_type") == "goal" and not tree.get("root_node_id"):
                    tree["root_node_id"] = node.get("node_id")
                progressed = True
            if not progressed:
                break
            pending = rest

        if not tree.get("root_node_id"):
            for nid in tree.get("node_ids") or []:
                if nodes.get(nid, {}).get("node_type") == "goal":
                    tree["root_node_id"] = nid
                    break
            if not tree.get("root_node_id") and tree.get("node_ids"):
                tree["root_node_id"] = tree["node_ids"][0]

    for dm in _list(delta.get("code_path_mappings")):
        if not isinstance(dm, dict):
            continue
        sid = node_id_map.get(dm.get("surface_node_id"))
        if not sid:
            continue
        mapping = mappings.get(sid)
        if not mapping:
            mapping = {"surface_node_id": sid, "code_paths": [], "status": "done", "origin": origin}
            mappings[sid] = mapping
            mappings_arr.append(mapping)
        paths = {cp.get("path") for cp in _list(mapping.get("code_paths")) if isinstance(cp, dict) and cp.get("path")}
        for cp in _list(dm.get("code_paths")):
            if not isinstance(cp, dict) or not cp.get("path") or cp.get("path") in paths:
                continue
            mapping.setdefault("code_paths", []).append({"path": cp.get("path"), "description": cp.get("description") or ""})
            paths.add(cp.get("path"))
            stats["code_paths"] += 1

    graph["assets"] = assets
    graph["trees"] = trees
    graph["nodes"] = list(nodes.values())
    graph["code_path_mappings"] = mappings_arr
    graph.setdefault("warnings", [])
    for w in _list(delta.get("warnings")):
        msg = f"{origin}: {w}" if origin else str(w)
        if msg not in graph["warnings"]:
            graph["warnings"].append(msg)
    return rebuild_graph(graph), stats

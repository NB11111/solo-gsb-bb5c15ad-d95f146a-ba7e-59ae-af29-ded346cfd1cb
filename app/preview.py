"""审计修复「影响预演」引擎（纯函数，无副作用，不依赖 FastAPI / SQLite）。

勾选修复建议后，在**不落库**的前提下：

1. 按与正式应用完全相同的**确定性应用顺序**在内存中生成草稿规则
   （复用 :func:`app.remediation.apply_suggestions_dry`，含"关系已被先前
   修复消除则跳过"语义）；
2. 分别用**当前规则**与**草稿规则**，对全部已注入告警按注入顺序
   （``seq`` 升序）**从零冷却状态**回放，保持与策略回放一致的注入顺序
   与冷却窗口语义（冷却指纹、乱序告警不移动冷却基准等全部沿用引擎）；
3. 汇总放行→抑制、抑制→放行以及**逐条规则归因变化**。

预演结果由一个绑定**规则快照、建议集合与告警集合**的令牌（token）背书：
令牌对三者与勾选建议的内容做 HMAC 签名，不携带规则/告警正文；正式应用
时在同一事务内复核令牌，任一输入已变化则以 409 拒绝且不修改规则。

本模块不读写任何数据库表（令牌签名密钥的持久化由路由层负责）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Optional, Sequence

from .engine import EvalState, RuleView, evaluate, ordered_rules
from .remediation import (
    apply_suggestions_dry,
    diff_audits,
    validate_remediation,
)

# ---------------------------------------------------------------------------
# 规范序列化与内容摘要（令牌绑定的三类输入 + 草稿规则）
# ---------------------------------------------------------------------------

def canonical_json(obj: Any) -> str:
    """键排序、无多余空白的 JSON 文本，保证内容相同的输入摘要一致。"""
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o),
    )


def digest(obj: Any) -> str:
    """对任意可 JSON 序列化内容计算稳定的十六进制摘要。"""
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


# 参与规则快照摘要的列（created_at 只是建表元数据，不参与评估语义）
RULE_HASH_KEYS = (
    "id", "name", "description", "action", "priority", "cooldown_seconds",
    "match_device", "match_batch", "match_level", "time_start", "time_end",
    "date_start", "date_end", "enabled",
)
# 参与告警集合摘要的列（注入顺序 seq 一并绑定；raw_json 不影响评估语义）
ALERT_HASH_KEYS = (
    "id", "seq", "device_id", "batch_id", "level", "alert_type", "message", "ts",
)


def rules_digest(rule_rows: Sequence[Any]) -> str:
    rows = [
        {k: (r[k] if not isinstance(r, dict) else r.get(k)) for k in RULE_HASH_KEYS}
        for r in rule_rows
    ]
    rows.sort(key=lambda r: r["id"])
    return digest(rows)


def alerts_digest(alert_rows: Sequence[Any]) -> str:
    rows = [
        {k: (r[k] if not isinstance(r, dict) else r.get(k)) for k in ALERT_HASH_KEYS}
        for r in alert_rows
    ]
    rows.sort(key=lambda r: (r["seq"], r["id"]))
    return digest(rows)


def suggestions_digest(suggestions: Sequence[dict]) -> str:
    """建议集合摘要：按建议 id 排序后的完整建议内容（含 ops 与目标规则）。"""
    return digest(sorted((dict(s) for s in suggestions),
                         key=lambda s: s.get("id", "")))


def draft_rules_digest(draft_rules: Sequence[Any]) -> str:
    return rules_digest(draft_rules)


# ---------------------------------------------------------------------------
# 令牌：绑定规则快照、建议集合、告警集合、勾选建议与草稿结果的 HMAC 签名
# ---------------------------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(secret: bytes, claims: dict) -> str:
    """对预演声明签发令牌：base64url(claims).base64url(HMAC-SHA256)。

    令牌不含规则/告警正文，只含四类内容摘要；密钥仅服务端持有，因此客户端
    无法伪造一份针对已变化输入的合法令牌。
    """
    payload = canonical_json(claims).encode("utf-8")
    sig = hmac.new(secret, payload, hashlib.sha256).digest()
    return f"{_b64e(payload)}.{_b64e(sig)}"


def verify_token(secret: bytes, token: str, expected: dict) -> list[str]:
    """复核令牌与当前输入是否一致，返回失配项列表（空列表 = 完全一致）。

    校验顺序：令牌结构与签名 → 勾选建议集合一致 → 规则快照 / 建议集合 /
    告警集合三个绑定摘要一致 → 草稿规则摘要一致（防御性）。任一绑定输入
    已变化都会列入返回值，由路由层转为 409 且不修改规则。
    """
    mismatches: list[str] = []
    try:
        part_payload, part_sig = token.split(".", 1)
        payload = _b64d(part_payload)
        given_sig = _b64d(part_sig)
    except (ValueError, TypeError):
        return ["令牌格式无效"]
    want_sig = hmac.new(secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(given_sig, want_sig):
        return ["令牌签名无效或来自旧密钥"]
    try:
        claims = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ["令牌内容无法解析"]
    if not isinstance(claims, dict):
        return ["令牌内容无效"]

    if sorted(claims.get("selected") or []) != sorted(expected.get("selected") or []):
        mismatches.append("勾选的建议集合已变化")
    for key, label in (
        ("rules", "规则快照"),
        ("suggestions", "建议集合"),
        ("alerts", "告警集合"),
        ("draft", "草稿规则"),
    ):
        if claims.get(key) != expected.get(key):
            mismatches.append(f"{label}已变化")
    return mismatches


# ---------------------------------------------------------------------------
# 从零回放（注入顺序 + 冷却状态语义与 /api/replays 完全一致）
# ---------------------------------------------------------------------------

def replay(alerts: Sequence[dict], rule_rows: Sequence[Any]) -> list[dict]:
    """用给定规则对告警按 seq 升序做从零冷却回放，返回逐条决定。

    规则可以是规则表 dict（含 enabled）或 :class:`~app.engine.RuleView`；
    告警需要已规范化的 ``ts``（datetime）字段。纯计算，不做任何 I/O。
    """
    rules: list[RuleView] = ordered_rules([dict(r) for r in rule_rows])
    state = EvalState()
    out: list[dict] = []
    for alert in sorted(alerts, key=lambda a: (a["seq"], a["id"])):
        result = evaluate(alert, rules, state)
        out.append({
            "alert_id": alert["id"],
            "seq": alert["seq"],
            "device_id": alert.get("device_id", ""),
            "batch_id": alert.get("batch_id", ""),
            "level": alert.get("level", "info"),
            "alert_type": alert.get("alert_type", ""),
            "message": alert.get("message", ""),
            "ts": alert["ts"].isoformat(timespec="seconds")
                  if hasattr(alert["ts"], "isoformat") else str(alert["ts"]),
            "decision": result["decision"],
            "rule_id": result["rule_id"],
            "rule_name": result["rule_name"],
            "reason": result["reason"],
        })
    return out


def _attribution(decisions: Sequence[dict]) -> dict[Optional[int], dict]:
    """按归因规则（含 None=默认放行）统计放行/抑制计数。"""
    stats: dict[Optional[int], dict] = {}

    def bucket(rule_id):
        return stats.setdefault(rule_id, {"rule_id": rule_id, "pass": 0, "suppress": 0})

    for d in decisions:
        bucket(d["rule_id"])[d["decision"]] += 1
    return stats


def build_preview(
    rule_rows: Sequence[Any],
    suggestions: Sequence[dict],
    selected_ids: Sequence[str],
    alerts: Sequence[dict],
) -> dict:
    """生成一次完整的影响预演（纯函数，不落库）。

    入参：规则表全量行、当前确定性建议集合、勾选的建议 id（非空）、
    已注入告警（dict，``ts`` 为 datetime，按 seq 排序回放）。
    返回草稿规则、逐条回放对比、放抑翻转汇总、逐条规则归因变化与
    应用后审计校验/对比结果。无已注入告警时各回放列表为空，仍为一次
    可应用的零变化预演。
    """
    dry = apply_suggestions_dry(rule_rows, suggestions, list(selected_ids))
    current_rows = [dict(r) for r in rule_rows]
    draft_rows = dry["draft_rules"]

    current_decisions = replay(alerts, current_rows)
    draft_decisions = replay(alerts, draft_rows)

    draft_by_alert = {d["alert_id"]: d for d in draft_decisions}

    rows_out = []
    pass_to_suppress = suppress_to_pass = 0
    cur_stats = _attribution(current_decisions)
    draft_stats = _attribution(draft_decisions)
    cur_names = {int(r["id"]): r.get("name") for r in current_rows}
    draft_names = {int(r["id"]): r.get("name") for r in draft_rows}

    def flip_kind(before: str, after: str) -> str:
        if before == "pass" and after == "suppress":
            return "pass_to_suppress"
        if before == "suppress" and after == "pass":
            return "suppress_to_pass"
        return "unchanged"

    for cd in current_decisions:
        dd = draft_by_alert[cd["alert_id"]]
        changed = cd["decision"] != dd["decision"]
        if changed:
            if cd["decision"] == "pass":
                pass_to_suppress += 1
            else:
                suppress_to_pass += 1
        rule_changed = cd["rule_id"] != dd["rule_id"]
        rows_out.append({
            "seq": cd["seq"],
            "device_id": cd["device_id"],
            "batch_id": cd["batch_id"],
            "level": cd["level"],
            "alert_type": cd["alert_type"],
            "message": cd["message"],
            "ts": cd["ts"],
            "before_decision": cd["decision"],
            "before_rule_id": cd["rule_id"],
            "before_rule_name": cd["rule_name"],
            "before_reason": cd["reason"],
            "after_decision": dd["decision"],
            "after_rule_id": dd["rule_id"],
            "after_rule_name": dd["rule_name"],
            "after_reason": dd["reason"],
            "decision_changed": changed,
            "flip": flip_kind(cd["decision"], dd["decision"]),
            "rule_attribution_changed": rule_changed,
        })

    # 逐条规则归因变化：计数变化或名称变化（被合并/收窄）的规则，
    # 另列出草稿中被删除的规则。None 表示"无命中规则（默认放行）"。
    deleted_ids = sorted(set(cur_names) - set(draft_names))
    all_rule_ids = sorted(set(cur_stats) | set(draft_stats),
                          key=lambda x: (x is None, x))
    attribution = []
    for rid in all_rule_ids:
        c = cur_stats.get(rid, {"pass": 0, "suppress": 0})
        a = draft_stats.get(rid, {"pass": 0, "suppress": 0})
        if c["pass"] == a["pass"] and c["suppress"] == a["suppress"]:
            continue
        attribution.append({
            "rule_id": rid,
            "rule_name": draft_names.get(rid) or cur_names.get(rid),
            "deleted": rid in deleted_ids,
            "before_pass": c["pass"],
            "before_suppress": c["suppress"],
            "after_pass": a["pass"],
            "after_suppress": a["suppress"],
            "pass_delta": a["pass"] - c["pass"],
            "suppress_delta": a["suppress"] - c["suppress"],
        })

    before, after = dry["before_audit"], dry["after_audit"]
    validation_errors = validate_remediation(before, after, dry["ordered"])
    audit_diff = diff_audits(before, after)

    def rule_brief(r: dict) -> dict:
        return {
            "id": int(r["id"]),
            "name": r.get("name", ""),
            "description": r.get("description", ""),
            "action": r.get("action"),
            "priority": r.get("priority"),
            "cooldown_seconds": r.get("cooldown_seconds", 0),
            "match_device": r.get("match_device", ""),
            "match_batch": r.get("match_batch", ""),
            "match_level": r.get("match_level", ""),
            "time_start": r.get("time_start", ""),
            "time_end": r.get("time_end", ""),
            "date_start": r.get("date_start", ""),
            "date_end": r.get("date_end", ""),
            "enabled": int(r.get("enabled", 1)),
        }

    changed_rule_ids = set()
    for s in dry["ordered"]:
        if any(x["status"] == "applied" for x in dry["results"]
               if x["suggestion_id"] == s["id"]):
            changed_rule_ids.update(s.get("target_rule_ids", []))
    changed_rule_ids.update(deleted_ids)

    return {
        "selected_ids": list(selected_ids),
        "results": dry["results"],
        "applied_count": sum(1 for r in dry["results"] if r["status"] == "applied"),
        "skipped_count": sum(1 for r in dry["results"] if r["status"] == "skipped"),
        "current_rules": [rule_brief(r) for r in
                          sorted(current_rows, key=lambda r: (r["priority"], r["id"]))],
        "draft_rules": [rule_brief(r) for r in
                        sorted(draft_rows, key=lambda r: (r["priority"], r["id"]))],
        "deleted_rule_ids": deleted_ids,
        "changed_rule_ids": sorted(changed_rule_ids),
        "replay": {
            "alert_count": len(alerts),
            "rows": rows_out,
            "before_pass": sum(1 for d in current_decisions if d["decision"] == "pass"),
            "before_suppress": sum(1 for d in current_decisions
                                   if d["decision"] == "suppress"),
            "after_pass": sum(1 for d in draft_decisions if d["decision"] == "pass"),
            "after_suppress": sum(1 for d in draft_decisions
                                  if d["decision"] == "suppress"),
            "pass_to_suppress": pass_to_suppress,
            "suppress_to_pass": suppress_to_pass,
            "changed_count": pass_to_suppress + suppress_to_pass,
        },
        "rule_attribution": attribution,
        "validation_errors": validation_errors,
        "validation_ok": not validation_errors,
        "audit_diff": audit_diff,
    }

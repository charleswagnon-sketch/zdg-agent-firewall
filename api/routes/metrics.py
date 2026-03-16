"""api/routes/metrics.py - GET /v1/metrics"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Request
from sqlmodel import Session, func, select

from api.auth import require_admin
from db.models import KillSwitchEvent, PolicyDecision
from db.sqlite import get_session

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/metrics")
def get_metrics(request: Request, session: Session = Depends(get_session)):
    state = request.app.state.zdg

    total = session.exec(select(func.count()).select_from(PolicyDecision)).one() or 0
    allowed = session.exec(
        select(func.count()).select_from(PolicyDecision).where(PolicyDecision.decision == "ALLOW")
    ).one() or 0
    blocked = session.exec(
        select(func.count()).select_from(PolicyDecision).where(PolicyDecision.decision == "BLOCK")
    ).one() or 0
    approval_req = session.exec(
        select(func.count()).select_from(PolicyDecision).where(PolicyDecision.decision == "APPROVAL_REQUIRED")
    ).one() or 0

    all_decisions = session.exec(select(PolicyDecision.triggered_rules)).all()
    rule_counts: dict[str, int] = {}
    for rules_json in all_decisions:
        if not rules_json:
            continue
        try:
            rules = json.loads(rules_json)
        except Exception:
            continue
        for rule in rules:
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda item: -item[1])[:10]

    reason_counts: dict[str, int] = {}
    for reason_code in session.exec(select(PolicyDecision.reason_code)).all():
        if reason_code:
            reason_counts[reason_code] = reason_counts.get(reason_code, 0) + 1
    top_codes = sorted(reason_counts.items(), key=lambda item: -item[1])[:10]

    global_active = session.exec(
        select(func.count()).select_from(KillSwitchEvent)
        .where(KillSwitchEvent.scope == "global")
        .where(KillSwitchEvent.reset_at.is_(None))
    ).one() or 0
    scoped_active = session.exec(
        select(func.count()).select_from(KillSwitchEvent)
        .where(KillSwitchEvent.scope != "global")
        .where(KillSwitchEvent.reset_at.is_(None))
    ).one() or 0

    return {
        "total_attempts": total,
        "total_allowed": allowed,
        "total_blocked": blocked,
        "total_approval_required": approval_req,
        "top_triggered_rules": [{"rule": rule, "count": count} for rule, count in top_rules],
        "top_reason_codes": [{"reason_code": reason_code, "count": count} for reason_code, count in top_codes],
        "active_policy_bundle": state.bundle.version,
        "kill_switch_global_active": global_active > 0,
        "kill_switch_scoped_active_count": scoped_active,
    }
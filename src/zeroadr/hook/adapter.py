from __future__ import annotations

from pathlib import Path

from zeroadr.core.events import EventType, RuntimeEvent, new_event
from zeroadr.hook.models import HookDecisionResponse, HookEvent
from zeroadr.llm.adjudication import LLMAdjudicator
from zeroadr.normalization.capability_mapper import map_capability
from zeroadr.policy.engine import PolicyEngine
from zeroadr.runtime.service import RuntimeDecisionService


class HookRuntime:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine | None = None,
        trace_path: Path | None = None,
        db_path: Path | None = None,
        adjudicator: LLMAdjudicator | None = None,
    ) -> None:
        self.service = RuntimeDecisionService(
            source_type="hook",
            policy_engine=policy_engine,
            trace_path=trace_path,
            db_path=db_path,
            adjudicator=adjudicator,
        )

    def handle(self, hook_event: HookEvent) -> HookDecisionResponse:
        event = hook_event_to_runtime_event(hook_event)
        result = self.service.evaluate(event)
        return HookDecisionResponse(
            action=result.decision.action,
            policy_id=result.decision.policy_id,
            reason=result.decision.reason,
            finding_ids=result.decision.finding_ids,
            event_id=result.event.event_id,
            decision_id=result.decision.decision_id,
            approval_id=result.approval_request.approval_id if result.approval_request else None,
            adjudication_id=(
                result.adjudication.adjudication_id if result.adjudication else None
            ),
        )


def hook_event_to_runtime_event(hook_event: HookEvent) -> RuntimeEvent:
    event_type = _runtime_event_type(hook_event)
    mapping = map_capability(hook_event.tool_name, hook_event.arguments)
    raw = hook_event.raw or hook_event.model_dump(mode="json")
    return new_event(
        event_type=event_type,
        source_type="hook",
        session_id=hook_event.session_id,
        request_id=hook_event.request_id,
        tool_name=hook_event.tool_name,
        capability=mapping.capability,
        arguments=hook_event.arguments,
        result=hook_event.result,
        error=hook_event.error,
        raw=raw,
    )


def _runtime_event_type(hook_event: HookEvent) -> EventType:
    if hook_event.hook_event_type == "pre_tool_use":
        return "tool.call.requested"
    if hook_event.error is not None:
        return "tool.call.failed"
    return "tool.call.completed"

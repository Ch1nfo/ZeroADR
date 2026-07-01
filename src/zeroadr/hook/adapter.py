from __future__ import annotations

from pathlib import Path

from zeroadr.core.events import EventType, RuntimeEvent, new_event
from zeroadr.core.approvals import new_approval_request
from zeroadr.core.policies import new_policy_decision
from zeroadr.hook.models import HookDecisionResponse, HookEvent
from zeroadr.llm.adjudication import LLMAdjudicator
from zeroadr.normalization.capability_mapper import map_capability
from zeroadr.policy.engine import PolicyEngine
from zeroadr.runtime.service import RuntimeDecisionService
from zeroadr.runtime.security_coordinator import RuntimeSecurityCoordinator, StageReviewer
from zeroadr.security.redaction import redact_event


class HookRuntime:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine | None = None,
        trace_path: Path | None = None,
        db_path: Path | None = None,
        adjudicator: LLMAdjudicator | None = None,
        stage_reviewer: StageReviewer | None = None,
    ) -> None:
        self.service = RuntimeDecisionService(
            source_type="hook",
            policy_engine=policy_engine,
            trace_path=trace_path,
            db_path=db_path,
            adjudicator=adjudicator,
        )
        self.coordinator = RuntimeSecurityCoordinator(
            policy_engine=self.service.policy_engine,
            store=self.service.store,
            reviewer=stage_reviewer,
        )

    def handle(self, hook_event: HookEvent) -> HookDecisionResponse:
        event = hook_event_to_runtime_event(hook_event)
        if hook_event.hook_event_type == "agent_input":
            if self.service.policy_engine.agent_input_gate is None:
                self.service.record(event)
                return HookDecisionResponse(
                    action="allow",
                    policy_id=None,
                    reason="Agent Input Gate is disabled.",
                    finding_ids=[],
                    event_id=event.event_id,
                )
            gate = self.coordinator.review_agent_input(event)
            policy_decision = new_policy_decision(
                policy_id="agent-input-gate",
                action=gate.effective_action,
                reason="Agent Input Gate reviewed the input.",
                session_id=event.session_id,
                event_id=event.event_id,
                finding_ids=[item.finding_id for item in gate.findings],
            )
            approval_id: str | None = None
            if self.service.store:
                self.service.store.save_policy_decision(policy_decision)
                if gate.effective_action == "require_approval":
                    approval = new_approval_request(
                        decision_id=policy_decision.decision_id,
                        session_id=event.session_id,
                        event_id=event.event_id,
                        request_id=event.request_id,
                        policy_id=policy_decision.policy_id,
                        reason=policy_decision.reason,
                        finding_ids=policy_decision.finding_ids,
                        tool_name=None,
                        capability="agent.input",
                        arguments=None,
                        stage="agent_input",
                        evidence_preview=redact_event(event).arguments,
                    )
                    self.service.store.save_approval_request(approval)
                    approval_id = approval.approval_id
            return HookDecisionResponse(
                action=gate.effective_action,
                policy_id=policy_decision.policy_id,
                reason=policy_decision.reason,
                finding_ids=[item.finding_id for item in gate.findings],
                event_id=event.event_id,
                decision_id=policy_decision.decision_id,
                approval_id=approval_id,
            )
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
    capability = "agent.input" if hook_event.hook_event_type == "agent_input" else mapping.capability
    raw = hook_event.raw or hook_event.model_dump(mode="json")
    return new_event(
        event_type=event_type,
        source_type="hook",
        session_id=hook_event.session_id,
        request_id=hook_event.request_id,
        tool_name=hook_event.tool_name,
        capability=capability,
        arguments=hook_event.arguments,
        result=hook_event.result,
        error=hook_event.error,
        raw=raw,
    )


def _runtime_event_type(hook_event: HookEvent) -> EventType:
    if hook_event.hook_event_type == "agent_input":
        return "agent.input.received"
    if hook_event.hook_event_type == "pre_tool_use":
        return "tool.call.requested"
    if hook_event.error is not None:
        return "tool.call.failed"
    return "tool.call.completed"

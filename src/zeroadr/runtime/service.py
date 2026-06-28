from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from zeroadr.core.approvals import ApprovalRequest, new_approval_request
from zeroadr.core.events import RuntimeEvent, SourceType, new_event
from zeroadr.core.findings import Finding
from zeroadr.core.ids import new_ulid
from zeroadr.core.policies import PolicyAction, PolicyDecision
from zeroadr.detection.engine import DetectionEngine
from zeroadr.llm.adjudication import (
    LLMAdjudicator,
    build_adjudication_payload,
    resolve_adjudication_action,
)
from zeroadr.llm.models import LLMAdjudication, LLMAdjudicationResult
from zeroadr.llm.provider import LLMProviderError
from zeroadr.policy.engine import LLMAdjudicationPolicy, PolicyEngine
from zeroadr.security.redaction import redact_event
from zeroadr.storage.database import SQLiteStore
from zeroadr.storage.jsonl import write_event_jsonl


@dataclass(frozen=True)
class RuntimeDecision:
    event: RuntimeEvent
    findings: list[Finding]
    decision: PolicyDecision
    policy_event: RuntimeEvent
    approval_request: ApprovalRequest | None = None
    adjudication: LLMAdjudication | None = None


_SAFE_ADJUDICATION_ERRORS = {
    "missing_llm_config": "LLM Gate is not configured.",
    "provider_timeout": "LLM Gate timed out.",
    "provider_connection_error": "LLM Gate provider connection failed.",
    "provider_http_error": "LLM Gate provider returned an HTTP error.",
    "invalid_provider_response": "LLM Gate provider response was invalid.",
    "invalid_model_output": "LLM Gate output did not match the required schema.",
    "unknown_evidence_reference": "LLM Gate referenced evidence that was not supplied.",
}


class RuntimeDecisionService:
    def __init__(
        self,
        *,
        source_type: SourceType,
        policy_engine: PolicyEngine | None = None,
        trace_path: Path | None = None,
        db_path: Path | None = None,
        adjudicator: LLMAdjudicator | None = None,
    ) -> None:
        self.source_type = source_type
        self.policy_engine = policy_engine or PolicyEngine()
        self.detector = DetectionEngine()
        self.trace_path = trace_path
        self.store = SQLiteStore(db_path) if db_path else None
        self.adjudicator = adjudicator

    def evaluate(self, event: RuntimeEvent) -> RuntimeDecision:
        self.record(event)
        findings = self.detector.detect(event)
        for finding in findings:
            if self.store:
                self.store.save_finding(finding)
        decision = self.policy_engine.evaluate(event, findings)
        adjudication: LLMAdjudication | None = None
        gate_policy = self.policy_engine.llm_adjudication_for(event, findings)
        if (
            gate_policy is not None
            and event.event_type == "tool.call.requested"
            and self.source_type in {"mcp_gateway", "hook"}
            and not any(finding.severity == "critical" for finding in findings)
        ):
            prepared = build_adjudication_payload(
                event,
                findings,
                policy_id=decision.policy_id or "unnamed-policy",
            )
            adjudication_id = new_ulid()
            try:
                if self.adjudicator is None:
                    raise LLMProviderError("missing_llm_config", "LLM Gate is not configured.")
                provider_result = self.adjudicator.adjudicate(
                    payload=prepared.payload,
                    evidence_refs=set(prepared.evidence_refs),
                )
                proposed_action = resolve_adjudication_action(
                    base_action=decision.action,
                    policy=gate_policy,
                    result=provider_result.result,
                    has_critical=False,
                )
                final_action = proposed_action
                adjudication = LLMAdjudication(
                    adjudication_id=adjudication_id,
                    session_id=event.session_id,
                    event_id=event.event_id,
                    finding_ids=[finding.finding_id for finding in findings],
                    policy_id=decision.policy_id or "unnamed-policy",
                    created_at=datetime.now(UTC),
                    status="completed",
                    mode=gate_policy.mode,
                    provider="openai-compatible",
                    model=self.adjudicator.model,
                    prompt_version=getattr(self.adjudicator, "prompt_version", "gate-v0.1"),
                    input_sha256=prepared.input_sha256,
                    result=provider_result.result,
                    proposed_action=(
                        _proposed_action(gate_policy, provider_result.result)
                    ),
                    final_action=final_action,
                    latency_ms=provider_result.latency_ms,
                    token_usage=provider_result.token_usage,
                    provider_request_id=provider_result.provider_request_id,
                )
                reason = (
                    f"LLM adjudication {adjudication_id}: {provider_result.result.reason}"
                )
            except LLMProviderError as exc:
                proposed_action = "require_approval"
                final_action = resolve_adjudication_action(
                    base_action=decision.action,
                    policy=gate_policy,
                    result=None,
                    has_critical=False,
                )
                safe_error = _SAFE_ADJUDICATION_ERRORS.get(
                    exc.code,
                    "LLM Gate failed.",
                )
                adjudication = LLMAdjudication(
                    adjudication_id=adjudication_id,
                    session_id=event.session_id,
                    event_id=event.event_id,
                    finding_ids=[finding.finding_id for finding in findings],
                    policy_id=decision.policy_id or "unnamed-policy",
                    created_at=datetime.now(UTC),
                    status="failed",
                    mode=gate_policy.mode,
                    provider="openai-compatible",
                    model=self.adjudicator.model if self.adjudicator else "unconfigured",
                    prompt_version=getattr(self.adjudicator, "prompt_version", "gate-v0.1"),
                    input_sha256=prepared.input_sha256,
                    result=None,
                    proposed_action=proposed_action,
                    final_action=final_action,
                    latency_ms=0,
                    error_code=exc.code,
                    error_message=safe_error,
                )
                reason = f"LLM adjudication {adjudication_id}: {safe_error}"
            if self.store:
                self.store.save_llm_adjudication(adjudication)
            decision = _decision_with_action(decision, final_action, reason)
        approval_request: ApprovalRequest | None = None
        if self.store:
            self.store.save_policy_decision(decision)
            if decision.action == "require_approval":
                redacted_event = redact_event(event)
                approval_request = new_approval_request(
                    decision_id=decision.decision_id,
                    session_id=decision.session_id,
                    event_id=decision.event_id,
                    request_id=event.request_id,
                    policy_id=decision.policy_id,
                    reason=decision.reason,
                    finding_ids=decision.finding_ids,
                    tool_name=event.tool_name,
                    capability=event.capability,
                    arguments=redacted_event.arguments if isinstance(redacted_event.arguments, dict) else None,
                )
                self.store.save_approval_request(approval_request)
        policy_result = {"action": decision.action, "policy_id": decision.policy_id}
        if adjudication is not None:
            policy_result["adjudication_id"] = adjudication.adjudication_id
        policy_event = new_event(
            event_type="policy.evaluated",
            source_type=self.source_type,
            session_id=event.session_id,
            request_id=event.request_id,
            server_name=event.server_name,
            tool_name=event.tool_name,
            capability=event.capability,
            arguments=event.arguments,
            result=policy_result,
            raw=decision.model_dump(mode="json"),
        )
        self.record(policy_event)
        return RuntimeDecision(
            event=event,
            findings=findings,
            decision=decision,
            policy_event=policy_event,
            approval_request=approval_request,
            adjudication=adjudication,
        )

    def record(self, event: RuntimeEvent) -> None:
        stored_event = redact_event(event)
        if self.trace_path:
            write_event_jsonl(self.trace_path, stored_event)
        if self.store:
            self.store.save_event(stored_event)


def _decision_with_action(
    decision: PolicyDecision,
    action: PolicyAction,
    reason: str,
) -> PolicyDecision:
    from zeroadr.core.policies import new_policy_decision

    return new_policy_decision(
        policy_id=decision.policy_id,
        action=action,
        reason=reason,
        session_id=decision.session_id,
        event_id=decision.event_id,
        finding_ids=decision.finding_ids,
    )


def _proposed_action(
    gate_policy: LLMAdjudicationPolicy,
    result: LLMAdjudicationResult,
) -> PolicyAction:
    if result.confidence < gate_policy.min_confidence or result.verdict == "uncertain":
        return "require_approval"
    if result.verdict == "likely_true_positive":
        return gate_policy.true_positive_action
    return gate_policy.false_positive_action

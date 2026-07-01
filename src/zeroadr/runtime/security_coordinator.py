from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
import hashlib
import time
from typing import Any, Callable, Protocol

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, new_finding
from zeroadr.core.policies import PolicyAction
from zeroadr.core.runtime_gate import GateStage, RuntimeGateRecord
from zeroadr.detection.engine import DetectionEngine
from zeroadr.llm.provider import LLMProviderError
from zeroadr.policy.engine import PolicyEngine, SemanticGatePolicy
from zeroadr.storage.database import SQLiteStore

_COMPROMISE_RULES = {
    "prompt-injection-agent-input",
    "prompt-injection-tool-result",
    "memory-poisoning-tool-result",
    "tool-metadata-backdoor",
}
_RISKY_CAPABILITIES = {
    "filesystem.write",
    "shell.exec",
    "network.connect",
    "network.http_post",
    "message.send",
    "email.send",
}


@dataclass(slots=True)
class SessionSecurityState:
    compromised: bool = False
    finding_ids: list[str] = field(default_factory=list)
    event_ids: deque[str] = field(default_factory=lambda: deque(maxlen=256))
    last_seen: float = field(default_factory=time.monotonic)
    input_preview: str | None = None
    tool_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeGateDecision:
    effective_action: PolicyAction
    findings: list[Finding]
    record: RuntimeGateRecord


class StageReviewer(Protocol):
    model: str

    def review(
        self,
        *,
        stage: GateStage,
        event: RuntimeEvent,
        findings: list[Finding],
        context: dict[str, Any],
    ) -> tuple[str, float, int]: ...


class RuntimeSecurityCoordinator:
    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        store: SQLiteStore | None = None,
        reviewer: StageReviewer | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy_engine = policy_engine
        self.detector = DetectionEngine()
        self.store = store
        self.reviewer = reviewer
        self.clock = clock
        self._sessions: dict[str, SessionSecurityState] = {}
        self._metadata_cache: OrderedDict[str, tuple[str, float, int]] = OrderedDict()

    def session_state(self, session_id: str) -> SessionSecurityState:
        self._expire()
        state = self._sessions.get(session_id)
        if state is None:
            state = SessionSecurityState(last_seen=self.clock())
            self._sessions[session_id] = state
        state.last_seen = self.clock()
        return state

    def mark_compromised(self, session_id: str, *, finding_ids: list[str]) -> None:
        state = self.session_state(session_id)
        state.compromised = True
        state.finding_ids = list(dict.fromkeys([*state.finding_ids, *finding_ids]))[-256:]

    def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def review_agent_input(self, event: RuntimeEvent) -> RuntimeGateDecision:
        content = event.arguments.get("content") if isinstance(event.arguments, dict) else None
        if isinstance(content, str):
            self.session_state(event.session_id).input_preview = content[:4096]
        return self._review(event, "agent_input", self.policy_engine.agent_input_gate)

    def review_tool_metadata(self, event: RuntimeEvent) -> RuntimeGateDecision:
        if event.tool_name and isinstance(event.arguments, dict):
            self.session_state(event.session_id).tool_metadata[event.tool_name] = {
                str(key): value
                for key, value in list(event.arguments.items())[:20]
                if key in {"name", "description", "inputSchema", "parameters"}
            }
        return self._review(event, "tool_metadata", self.policy_engine.tool_metadata_gate)

    def review_tool_request(self, event: RuntimeEvent) -> RuntimeGateDecision:
        return self._review(event, "pre_tool", self.policy_engine.tool_request_gate)

    def observe_result(self, event: RuntimeEvent) -> list[Finding]:
        findings = self.detector.detect(event)
        self._update_state(event, findings)
        return findings

    def observe_findings(self, event: RuntimeEvent, findings: list[Finding]) -> None:
        self._update_state(event, findings)

    def _review(
        self,
        event: RuntimeEvent,
        stage: GateStage,
        gate: SemanticGatePolicy | None,
    ) -> RuntimeGateDecision:
        started = self.clock()
        state = self.session_state(event.session_id)
        findings = self.detector.detect(event)
        if stage == "pre_tool" and state.compromised and (
            event.capability is None
            or event.capability in _RISKY_CAPABILITIES
            or any(item.rule_id == "sensitive-file-access" for item in findings)
        ):
            findings.append(
                new_finding(
                    rule_id="online-compromised-session-action",
                    title="Compromised session attempted a risky action",
                    severity="critical",
                    confidence=0.99,
                    session_id=event.session_id,
                    event_ids=[event.event_id],
                    capability=event.capability or "tool.call",
                    target=event.tool_name or "unknown_tool",
                    explanation="A session with prior injection evidence attempted a risky action.",
                )
            )
        base = self.policy_engine.evaluate(event, findings).action
        if base == "alert":
            base = "allow"
        proposed: PolicyAction = base
        verdict: str | None = None
        confidence: float | None = None
        error_code: str | None = None
        has_critical = any(item.severity == "critical" for item in findings)
        if gate is not None and has_critical:
            proposed = _normalize_gate_action(gate.true_positive_action)
        elif gate is not None and gate.review == "hybrid" and self._should_review(stage, event, findings, state):
            try:
                verdict, confidence, _review_latency = self._semantic_review(
                    stage=stage,
                    event=event,
                    findings=findings,
                    gate=gate,
                )
                if confidence < gate.min_confidence or verdict == "uncertain":
                    proposed = "require_approval"
                elif verdict == "likely_true_positive":
                    proposed = _normalize_gate_action(gate.true_positive_action)
                else:
                    proposed = _normalize_gate_action(gate.false_positive_action)
            except LLMProviderError as exc:
                proposed = "require_approval"
                error_code = exc.code
            except Exception:
                proposed = "require_approval"
                error_code = "stage_reviewer_error"
        if (
            stage == "pre_tool"
            and state.compromised
            and self.policy_engine.session_guard is not None
            and any(item.rule_id == "online-compromised-session-action" for item in findings)
        ):
            proposed = _normalize_gate_action(
                self.policy_engine.session_guard.compromised_action
            )
        effective: PolicyAction = proposed
        if gate is not None and gate.mode == "shadow":
            effective = "allow"
        if self.policy_engine.session_guard is not None and self.policy_engine.session_guard.mode == "shadow" and proposed == self.policy_engine.session_guard.compromised_action:
            effective = "allow"
        self._update_state(event, findings)
        state = self.session_state(event.session_id)
        record = RuntimeGateRecord.new(
            session_id=event.session_id,
            event_id=event.event_id,
            stage=stage,
            mode=gate.mode if gate is not None else "shadow",
            review=gate.review if gate is not None else "rules",
            base_action=base,
            proposed_action=proposed,
            effective_action=effective,
            finding_ids=[item.finding_id for item in findings],
            rule_ids=[item.rule_id for item in findings],
            capability=event.capability,
            target_sha256=(
                hashlib.sha256((event.tool_name or "").encode()).hexdigest()
                if event.tool_name
                else None
            ),
            schema_sha256=(
                _stable_hash(event.arguments)
                if stage == "tool_metadata" and event.arguments is not None
                else None
            ),
            session_compromised=state.compromised,
            verdict=verdict,
            confidence=confidence,
            error_code=error_code,
            latency_ms=max(0, round((self.clock() - started) * 1000)),
        )
        if self.store:
            self.store.save_event(event)
            for finding in findings:
                self.store.save_finding(finding)
            self.store.save_runtime_gate_record(record)
        return RuntimeGateDecision(effective, findings, record)

    def _should_review(
        self,
        stage: GateStage,
        event: RuntimeEvent,
        findings: list[Finding],
        state: SessionSecurityState,
    ) -> bool:
        if stage in {"agent_input", "tool_metadata"}:
            return True
        if stage != "pre_tool":
            return False
        return (
            state.compromised
            or event.capability is None
            or event.capability in _RISKY_CAPABILITIES
            or bool(findings)
        )

    def _semantic_review(
        self,
        *,
        stage: GateStage,
        event: RuntimeEvent,
        findings: list[Finding],
        gate: SemanticGatePolicy,
    ) -> tuple[str, float, int]:
        if self.reviewer is None:
            raise RuntimeError("stage reviewer is not configured")
        cache_key: str | None = None
        if stage == "tool_metadata":
            cache_key = self._metadata_cache_key(event, gate)
            cached = self._metadata_cache.get(cache_key)
            if cached is not None:
                self._metadata_cache.move_to_end(cache_key)
                return cached
        result = self.reviewer.review(
            stage=stage,
            event=event,
            findings=findings,
            context={
                "session_compromised": self.session_state(event.session_id).compromised,
                "prior_finding_ids": self.session_state(event.session_id).finding_ids,
                "agent_input": self.session_state(event.session_id).input_preview,
                "tool_metadata": (
                    self.session_state(event.session_id).tool_metadata.get(event.tool_name or "")
                ),
            },
        )
        if cache_key is not None:
            self._metadata_cache[cache_key] = result
            self._metadata_cache.move_to_end(cache_key)
            while len(self._metadata_cache) > 1024:
                self._metadata_cache.popitem(last=False)
        return result

    def _metadata_cache_key(self, event: RuntimeEvent, gate: SemanticGatePolicy) -> str:
        import json

        payload = {
            "schema": event.arguments,
            "model": getattr(self.reviewer, "model", "unconfigured"),
            "prompt_version": getattr(self.reviewer, "prompt_version", "runtime-stage-v0.1"),
            "gate": gate.model_dump(mode="json"),
        }
        return hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _update_state(self, event: RuntimeEvent, findings: list[Finding]) -> None:
        state = self.session_state(event.session_id)
        state.event_ids.append(event.event_id)
        compromising = [item.finding_id for item in findings if item.rule_id in _COMPROMISE_RULES]
        if compromising:
            self.mark_compromised(event.session_id, finding_ids=compromising)

    def _expire(self) -> None:
        now = self.clock()
        expired = [key for key, value in self._sessions.items() if now - value.last_seen > 3600]
        for key in expired:
            self._sessions.pop(key, None)


def _normalize_gate_action(action: PolicyAction) -> PolicyAction:
    return "allow" if action == "alert" else action


def _stable_hash(value: object) -> str:
    import json

    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

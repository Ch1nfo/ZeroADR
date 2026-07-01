from __future__ import annotations

from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from zeroadr.core.policies import PolicyAction

AnalysisStatus = Literal["completed", "failed"]
AnalysisLanguage = Literal["zh", "en"]
AnalysisVerdict = Literal[
    "likely_true_positive",
    "uncertain",
    "likely_false_positive",
]
RiskLevel = Literal["low", "medium", "high", "critical"]
AdjudicationMode = Literal["shadow", "enforce"]


class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class LLMAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: AnalysisVerdict
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    rationale: str
    attack_chain: list[str]
    recommended_actions: list[str]
    evidence_refs: list[str]
    limitations: list[str]


class LLMAdjudicationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: AnalysisVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    evidence_refs: list[str]
    limitations: list[str]


class LLMAdjudication(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adjudication_id: str
    session_id: str
    event_id: str
    finding_ids: list[str]
    policy_id: str
    created_at: datetime
    status: AnalysisStatus
    mode: AdjudicationMode
    stage: Literal["agent_input", "tool_metadata", "pre_tool", "tool_result"] = "pre_tool"
    provider: str
    model: str
    prompt_version: str
    input_sha256: str
    result: LLMAdjudicationResult | None = None
    proposed_action: PolicyAction
    final_action: PolicyAction
    latency_ms: int = Field(ge=0)
    token_usage: TokenUsage | None = None
    provider_request_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    @model_validator(mode="after")
    def validate_status_payload(self) -> Self:
        if self.status == "completed":
            if self.result is None:
                raise ValueError("completed adjudication requires a result")
            if self.error_code is not None or self.error_message is not None:
                raise ValueError("completed adjudication cannot contain an error")
        else:
            if self.result is not None:
                raise ValueError("failed adjudication cannot contain a result")
            if self.error_code is None or self.error_message is None:
                raise ValueError("failed adjudication requires an error code and message")
        return self


class LLMAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    session_id: str
    created_at: datetime
    status: AnalysisStatus
    provider: str
    base_url: str
    model: str
    prompt_version: str
    language: AnalysisLanguage
    input_sha256: str
    finding_ids: list[str]
    event_ids: list[str]
    result: LLMAnalysisResult | None = None
    latency_ms: int = Field(ge=0)
    token_usage: TokenUsage | None = None
    provider_request_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    @model_validator(mode="after")
    def validate_status_payload(self) -> Self:
        if self.status == "completed":
            if self.result is None:
                raise ValueError("completed analysis requires a result")
            if self.error_code is not None or self.error_message is not None:
                raise ValueError("completed analysis cannot contain an error")
        else:
            if self.result is not None:
                raise ValueError("failed analysis cannot contain a result")
            if self.error_code is None or self.error_message is None:
                raise ValueError("failed analysis requires an error code and message")
        return self

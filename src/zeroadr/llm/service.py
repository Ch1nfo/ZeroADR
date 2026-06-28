from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from zeroadr.core.ids import new_ulid
from zeroadr.llm.config import LLMConfig
from zeroadr.llm.models import LLMAnalysis
from zeroadr.llm.payload import build_triage_payload
from zeroadr.llm.provider import LLMProvider, LLMProviderError, OpenAICompatibleProvider
from zeroadr.reconstruction.session import reconstruct_from_sqlite
from zeroadr.storage.database import SQLiteStore

PROMPT_VERSION = "triage-v0.1"

_SAFE_PROVIDER_MESSAGES = {
    "provider_timeout": "Provider request timed out.",
    "provider_connection_error": "Provider connection failed.",
    "provider_http_error": "Provider returned an HTTP error.",
    "invalid_provider_response": "Provider response was invalid.",
    "invalid_model_output": "Model output did not match the triage schema.",
    "unknown_evidence_reference": "Model output referenced evidence that was not supplied.",
    "provider_error": "Provider request failed.",
}


class LLMTriageError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        analysis: LLMAnalysis | None = None,
    ) -> None:
        self.code = code
        self.analysis = analysis
        super().__init__(message)


def analyze_session(
    session_id: str,
    *,
    db_path: Path,
    config: LLMConfig,
    provider: LLMProvider | None = None,
) -> LLMAnalysis:
    store = SQLiteStore(db_path)
    if session_id not in store.list_sessions():
        raise LLMTriageError("session_not_found", f"Session not found: {session_id}")
    context = reconstruct_from_sqlite(session_id, db_path)
    prepared = build_triage_payload(context)
    active_provider = provider or OpenAICompatibleProvider(
        base_url=config.base_url,
        api_key=config.api_key,
        timeout=config.timeout,
    )
    evidence_refs = set(prepared.finding_ids) | set(prepared.event_ids)
    started = time.monotonic()
    try:
        provider_result = active_provider.analyze(
            payload=prepared.payload,
            evidence_refs=evidence_refs,
            model=config.model,
            language=config.language,
            max_output_tokens=config.max_output_tokens,
        )
    except LLMProviderError as exc:
        safe_message = _SAFE_PROVIDER_MESSAGES.get(exc.code, "Provider request failed.")
        failed = LLMAnalysis(
            analysis_id=new_ulid(),
            session_id=session_id,
            created_at=datetime.now(UTC),
            status="failed",
            provider="openai-compatible",
            base_url=config.base_url,
            model=config.model,
            prompt_version=PROMPT_VERSION,
            language=config.language,
            input_sha256=prepared.input_sha256,
            finding_ids=prepared.finding_ids,
            event_ids=prepared.event_ids,
            result=None,
            latency_ms=max(0, round((time.monotonic() - started) * 1000)),
            token_usage=None,
            provider_request_id=None,
            error_code=exc.code,
            error_message=safe_message,
        )
        store.save_llm_analysis(failed)
        raise LLMTriageError(exc.code, safe_message, analysis=failed) from exc
    completed = LLMAnalysis(
        analysis_id=new_ulid(),
        session_id=session_id,
        created_at=datetime.now(UTC),
        status="completed",
        provider="openai-compatible",
        base_url=config.base_url,
        model=config.model,
        prompt_version=PROMPT_VERSION,
        language=config.language,
        input_sha256=prepared.input_sha256,
        finding_ids=prepared.finding_ids,
        event_ids=prepared.event_ids,
        result=provider_result.result,
        latency_ms=provider_result.latency_ms,
        token_usage=provider_result.token_usage,
        provider_request_id=provider_result.provider_request_id,
        error_code=None,
        error_message=None,
    )
    store.save_llm_analysis(completed)
    return completed

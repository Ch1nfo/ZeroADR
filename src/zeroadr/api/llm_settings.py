from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

import httpx

from zeroadr.llm.config import (
    DEFAULT_LLM_BASE_URL,
    DEFAULT_LLM_LANGUAGE,
    DEFAULT_LLM_MAX_OUTPUT_TOKENS,
    DEFAULT_LLM_TIMEOUT,
    LLMConfigurationError,
    LLMFileConfig,
    load_llm_file_config,
    resolve_llm_config,
    resolve_llm_gate_config,
    save_llm_file_config,
)
from zeroadr.llm.adjudication import OpenAICompatibleAdjudicator
from zeroadr.llm.provider import OpenAICompatibleProvider

_CONFIG_FIELDS = {
    "schema_version",
    "base_url",
    "model",
    "api_key",
    "language",
    "timeout",
    "max_output_tokens",
    "gate_model",
    "gate_timeout",
    "gate_max_output_tokens",
    "clear_api_key",
}


def build_llm_config_view(
    path: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    values = os.environ if environ is None else environ
    saved = load_llm_file_config(path)
    base_url, base_url_source = _effective_value(
        (values.get("ZEROADR_LLM_BASE_URL"), "ZEROADR_LLM_BASE_URL"),
        (values.get("OPENAI_BASE_URL"), "OPENAI_BASE_URL"),
        (saved.base_url if saved else None, "file"),
        (DEFAULT_LLM_BASE_URL, "default"),
    )
    model, model_source = _effective_value(
        (values.get("ZEROADR_LLM_MODEL"), "ZEROADR_LLM_MODEL"),
        (values.get("OPENAI_MODEL"), "OPENAI_MODEL"),
        (saved.model if saved else None, "file"),
        (None, "unset"),
    )
    api_key, api_key_source = _effective_value(
        (values.get("ZEROADR_LLM_API_KEY"), "ZEROADR_LLM_API_KEY"),
        (values.get("OPENAI_API_KEY"), "OPENAI_API_KEY"),
        (saved.api_key if saved else None, "file"),
        (None, "unset"),
    )
    language, language_source = _effective_value(
        (values.get("ZEROADR_LLM_LANGUAGE"), "ZEROADR_LLM_LANGUAGE"),
        (saved.language if saved else None, "file"),
        (DEFAULT_LLM_LANGUAGE, "default"),
    )
    timeout, timeout_source = _effective_value(
        (values.get("ZEROADR_LLM_TIMEOUT"), "ZEROADR_LLM_TIMEOUT"),
        (saved.timeout if saved else None, "file"),
        (DEFAULT_LLM_TIMEOUT, "default"),
    )
    max_tokens, max_tokens_source = _effective_value(
        (values.get("ZEROADR_LLM_MAX_OUTPUT_TOKENS"), "ZEROADR_LLM_MAX_OUTPUT_TOKENS"),
        (saved.max_output_tokens if saved else None, "file"),
        (DEFAULT_LLM_MAX_OUTPUT_TOKENS, "default"),
    )
    saved_key = saved.api_key if saved else None
    return {
        "schema_version": "0.1",
        "config_path": str(path),
        "saved": {
            "base_url": saved.base_url if saved else DEFAULT_LLM_BASE_URL,
            "model": saved.model if saved else "",
            "language": saved.language if saved else DEFAULT_LLM_LANGUAGE,
            "timeout": saved.timeout if saved else DEFAULT_LLM_TIMEOUT,
            "max_output_tokens": (
                saved.max_output_tokens if saved else DEFAULT_LLM_MAX_OUTPUT_TOKENS
            ),
            "gate_model": saved.gate_model if saved else "",
            "gate_timeout": saved.gate_timeout if saved else 8.0,
            "gate_max_output_tokens": saved.gate_max_output_tokens if saved else 256,
        },
        "effective": {
            "base_url": base_url,
            "model": model or "",
            "language": language,
            "timeout": float(timeout),
            "max_output_tokens": int(max_tokens),
            "gate_model": (
                values.get("ZEROADR_LLM_GATE_MODEL")
                or (saved.gate_model if saved else None)
                or model
                or ""
            ),
            "gate_timeout": float(
                values.get("ZEROADR_LLM_GATE_TIMEOUT")
                or (saved.gate_timeout if saved else 8.0)
            ),
            "gate_max_output_tokens": int(
                values.get("ZEROADR_LLM_GATE_MAX_OUTPUT_TOKENS")
                or (saved.gate_max_output_tokens if saved else 256)
            ),
        },
        "sources": {
            "base_url": base_url_source,
            "model": model_source,
            "api_key": api_key_source,
            "language": language_source,
            "timeout": timeout_source,
            "max_output_tokens": max_tokens_source,
        },
        "api_key_configured": bool(api_key),
        "api_key_saved": bool(saved_key),
        "api_key_masked": _mask_secret(saved_key or api_key),
        "environment_override": any(
            source not in {"file", "default", "unset"}
            for source in (
                base_url_source,
                model_source,
                api_key_source,
                language_source,
                timeout_source,
                max_tokens_source,
            )
        ),
    }


def update_llm_config(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    unknown = set(payload) - _CONFIG_FIELDS
    if unknown:
        raise LLMConfigurationError("invalid_config", "LLM configuration contains unknown fields.")
    saved = load_llm_file_config(path)
    existing: dict[str, Any] = (
        saved.model_dump(mode="json")
        if saved
        else {
            "schema_version": "0.1",
            "base_url": DEFAULT_LLM_BASE_URL,
            "model": "",
            "api_key": None,
            "language": DEFAULT_LLM_LANGUAGE,
            "timeout": DEFAULT_LLM_TIMEOUT,
            "max_output_tokens": DEFAULT_LLM_MAX_OUTPUT_TOKENS,
        }
    )
    for field in (
        "schema_version",
        "base_url",
        "model",
        "language",
        "timeout",
        "max_output_tokens",
        "gate_model",
        "gate_timeout",
        "gate_max_output_tokens",
    ):
        if field in payload:
            existing[field] = payload[field]
    api_key = payload.get("api_key")
    if payload.get("clear_api_key") is True:
        existing["api_key"] = None
    elif isinstance(api_key, str) and api_key.strip():
        existing["api_key"] = api_key
    save_llm_file_config(path, LLMFileConfig.model_validate(existing))
    return build_llm_config_view(path)


def test_llm_config(
    path: Path,
    *,
    target: str = "triage",
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    if target not in {"triage", "gate"}:
        raise LLMConfigurationError(
            "invalid_test_target",
            "LLM connection test target must be triage or gate.",
        )
    if target == "gate":
        gate = resolve_llm_gate_config(config_path=path)
        adjudicator = OpenAICompatibleAdjudicator(
            base_url=gate.base_url,
            api_key=gate.api_key,
            model=gate.model,
            timeout=gate.timeout,
            max_output_tokens=gate.max_output_tokens,
            transport=transport,
        )
        gate_result = adjudicator.adjudicate(
            payload={
                "policy_id": "connection-test",
                "event": {
                    "event_id": "event_connection_test",
                    "event_type": "tool.call.requested",
                    "capability": "connection.test",
                },
                "findings": [],
            },
            evidence_refs={"event_connection_test"},
        )
        return {
            "connected": True,
            "target": "gate",
            "model": gate.model,
            "latency_ms": gate_result.latency_ms,
            "provider_request_id": gate_result.provider_request_id,
        }

    config = resolve_llm_config(
        base_url=None,
        model=None,
        language=None,
        timeout=None,
        max_output_tokens=None,
        config_path=path,
    )
    provider = OpenAICompatibleProvider(
        base_url=config.base_url,
        api_key=config.api_key,
        timeout=config.timeout,
        transport=transport,
    )
    connection_result = provider.test_connection(
        model=config.model,
        max_output_tokens=config.max_output_tokens,
    )
    return {
        "connected": True,
        "target": "triage",
        "model": config.model,
        "latency_ms": connection_result.latency_ms,
        "provider_request_id": connection_result.provider_request_id,
    }


def _effective_value(*candidates: tuple[Any, str]) -> tuple[Any, str]:
    for value, source in candidates:
        if value is not None and (not isinstance(value, str) or value.strip()):
            return (value.strip() if isinstance(value, str) else value), source
    return None, "unset"


def _mask_secret(value: str | None) -> str | None:
    if not value:
        return None
    suffix = value[-4:] if len(value) >= 4 else value
    return f"••••••••{suffix}"

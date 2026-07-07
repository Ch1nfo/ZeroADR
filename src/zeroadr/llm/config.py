from __future__ import annotations

import os
import json
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from zeroadr.llm.models import AnalysisLanguage

DEFAULT_LLM_BASE_URL = "https://api.openai.com/v1"
DEFAULT_LLM_CONFIG_PATH = Path(".zeroadr/llm-config.json")
DEFAULT_LLM_LANGUAGE: AnalysisLanguage = "zh"
DEFAULT_LLM_TIMEOUT = 5.0
DEFAULT_LLM_MAX_OUTPUT_TOKENS = 1200
DEFAULT_LLM_GATE_TIMEOUT = 8.0
DEFAULT_LLM_GATE_MAX_OUTPUT_TOKENS = 256


class LLMConfigurationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    api_key: str
    model: str
    language: AnalysisLanguage
    timeout: float
    max_output_tokens: int


@dataclass(frozen=True)
class LLMGateConfig:
    base_url: str
    api_key: str
    model: str
    timeout: float
    max_output_tokens: int


class LLMFileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="0.1", pattern=r"^0\.1$")
    base_url: str = DEFAULT_LLM_BASE_URL
    model: str
    api_key: str | None = None
    language: AnalysisLanguage = DEFAULT_LLM_LANGUAGE
    timeout: float = Field(default=DEFAULT_LLM_TIMEOUT, gt=0)
    max_output_tokens: int = Field(default=DEFAULT_LLM_MAX_OUTPUT_TOKENS, gt=0)
    gate_model: str | None = None
    gate_timeout: float = Field(default=DEFAULT_LLM_GATE_TIMEOUT, gt=0)
    gate_max_output_tokens: int = Field(default=DEFAULT_LLM_GATE_MAX_OUTPUT_TOKENS, gt=0)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return _validated_base_url(value)

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("LLM model must not be empty.")
        return normalized

    @field_validator("api_key")
    @classmethod
    def normalize_api_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("gate_model")
    @classmethod
    def normalize_gate_model(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


def load_llm_file_config(path: Path = DEFAULT_LLM_CONFIG_PATH) -> LLMFileConfig | None:
    if not path.exists():
        return None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise LLMConfigurationError("config_read_error", "Unable to inspect LLM config file.") from exc
    if mode & 0o077:
        raise LLMConfigurationError(
            "insecure_config_permissions",
            "LLM config file permissions must be 0600.",
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return LLMFileConfig.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError, TypeError) as exc:
        raise LLMConfigurationError("invalid_config_file", "LLM config file is invalid.") from exc


def save_llm_file_config(
    path: Path,
    config: LLMFileConfig | Mapping[str, Any],
) -> LLMFileConfig:
    try:
        validated = config if isinstance(config, LLMFileConfig) else LLMFileConfig.model_validate(config)
    except ValidationError as exc:
        raise LLMConfigurationError("invalid_config", "LLM configuration is invalid.") from exc
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(validated.model_dump(mode="json"), handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            path.chmod(0o600)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()
    except OSError as exc:
        raise LLMConfigurationError("config_write_error", "Unable to save LLM config file.") from exc
    return validated


def resolve_llm_config(
    *,
    base_url: str | None,
    model: str | None,
    language: AnalysisLanguage | None,
    timeout: float | None,
    max_output_tokens: int | None,
    config_path: Path = DEFAULT_LLM_CONFIG_PATH,
    environ: Mapping[str, str] | None = None,
) -> LLMConfig:
    values = os.environ if environ is None else environ
    file_config = load_llm_file_config(config_path)
    resolved_base_url = _first_value(
        base_url,
        values.get("ZEROADR_LLM_BASE_URL"),
        values.get("OPENAI_BASE_URL"),
        file_config.base_url if file_config else None,
        DEFAULT_LLM_BASE_URL,
    )
    resolved_model = _first_value(
        model,
        values.get("ZEROADR_LLM_MODEL"),
        values.get("OPENAI_MODEL"),
        file_config.model if file_config else None,
    )
    api_key = _first_value(
        values.get("ZEROADR_LLM_API_KEY"),
        values.get("OPENAI_API_KEY"),
        file_config.api_key if file_config else None,
    )
    resolved_language = _language_value(
        language,
        values.get("ZEROADR_LLM_LANGUAGE"),
        file_config.language if file_config else None,
    )
    resolved_timeout = _positive_float(
        timeout,
        values.get("ZEROADR_LLM_TIMEOUT"),
        file_config.timeout if file_config else None,
        default=DEFAULT_LLM_TIMEOUT,
        code="invalid_timeout",
        label="LLM timeout",
    )
    resolved_max_output_tokens = _positive_int(
        max_output_tokens,
        values.get("ZEROADR_LLM_MAX_OUTPUT_TOKENS"),
        file_config.max_output_tokens if file_config else None,
        default=DEFAULT_LLM_MAX_OUTPUT_TOKENS,
        code="invalid_max_output_tokens",
        label="LLM max output tokens",
    )
    if not resolved_model:
        raise LLMConfigurationError(
            "missing_model",
            "LLM model is required via --model, ZEROADR_LLM_MODEL, or OPENAI_MODEL.",
        )
    if not api_key:
        raise LLMConfigurationError(
            "missing_api_key",
            "LLM API key is required via ZEROADR_LLM_API_KEY or OPENAI_API_KEY.",
        )
    assert resolved_base_url is not None
    return LLMConfig(
        base_url=_validated_base_url(resolved_base_url),
        api_key=api_key,
        model=resolved_model,
        language=resolved_language,
        timeout=resolved_timeout,
        max_output_tokens=resolved_max_output_tokens,
    )


def resolve_llm_gate_config(
    *,
    config_path: Path = DEFAULT_LLM_CONFIG_PATH,
    environ: Mapping[str, str] | None = None,
) -> LLMGateConfig:
    values = os.environ if environ is None else environ
    base = resolve_llm_config(
        base_url=None,
        model=None,
        language=None,
        timeout=None,
        max_output_tokens=None,
        config_path=config_path,
        environ=values,
    )
    file_config = load_llm_file_config(config_path)
    model = _first_value(
        values.get("ZEROADR_LLM_GATE_MODEL"),
        file_config.gate_model if file_config else None,
        base.model,
    )
    timeout = _positive_float(
        values.get("ZEROADR_LLM_GATE_TIMEOUT"),
        file_config.gate_timeout if file_config else None,
        default=DEFAULT_LLM_GATE_TIMEOUT,
        code="invalid_gate_timeout",
        label="LLM Gate timeout",
    )
    max_output_tokens = _positive_int(
        values.get("ZEROADR_LLM_GATE_MAX_OUTPUT_TOKENS"),
        file_config.gate_max_output_tokens if file_config else None,
        default=DEFAULT_LLM_GATE_MAX_OUTPUT_TOKENS,
        code="invalid_gate_max_output_tokens",
        label="LLM Gate max output tokens",
    )
    assert model is not None
    return LLMGateConfig(
        base_url=base.base_url,
        api_key=base.api_key,
        model=model,
        timeout=timeout,
        max_output_tokens=max_output_tokens,
    )


def _first_value(*values: str | None) -> str | None:
    for value in values:
        if value is not None and value.strip():
            return value.strip()
    return None


def _validated_base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("LLM base URL must be HTTP or HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("LLM base URL must not contain credentials.")
    return normalized


def _language_value(*values: object) -> AnalysisLanguage:
    for value in values:
        if value in {"zh", "en"}:
            return value  # type: ignore[return-value]
        if value is not None:
            raise LLMConfigurationError("invalid_language", "LLM language must be zh or en.")
    return DEFAULT_LLM_LANGUAGE


def _positive_float(
    *values: str | int | float | None,
    default: float,
    code: str,
    label: str,
) -> float:
    for value in values:
        if value is None or value == "":
            continue
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise LLMConfigurationError(code, f"{label} must be positive.") from exc
        if parsed <= 0:
            raise LLMConfigurationError(code, f"{label} must be positive.")
        return parsed
    return default


def _positive_int(
    *values: str | int | float | None,
    default: int,
    code: str,
    label: str,
) -> int:
    for value in values:
        if value is None or value == "":
            continue
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise LLMConfigurationError(code, f"{label} must be positive.") from exc
        if parsed <= 0:
            raise LLMConfigurationError(code, f"{label} must be positive.")
        return parsed
    return default

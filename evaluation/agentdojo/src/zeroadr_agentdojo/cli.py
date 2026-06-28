from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from zeroadr.llm.config import (
    LLMConfigurationError,
    resolve_llm_config,
    resolve_llm_gate_config,
)
from zeroadr_agentdojo.adapter import (
    AgentDojoBenchmarkError,
    AgentDojoUnavailableError,
    run_agentdojo_benchmark,
    run_agentdojo_detector_benchmark,
)
from zeroadr_agentdojo.hybrid import run_agentdojo_hybrid_benchmark


DEFAULT_OUTPUT_DIR = Path(".zeroadr/evaluations/agentdojo")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zeroadr-agentdojo")
    subparsers = parser.add_subparsers(dest="command_name")

    agent = subparsers.add_parser("agent")
    _add_corpus_filters(agent)
    agent.add_argument("--logdir", default=str(DEFAULT_OUTPUT_DIR / "runs"))
    agent.add_argument("--model")
    agent.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    agent.add_argument("--force-rerun", action="store_true")
    agent.add_argument("--defense", choices=["zeroadr", "none"], default="zeroadr")

    detector = subparsers.add_parser("detector")
    _add_corpus_filters(detector)

    hybrid = subparsers.add_parser("hybrid")
    _add_corpus_filters(hybrid)
    hybrid.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    hybrid.add_argument("--cache", default=str(DEFAULT_OUTPUT_DIR / "hybrid-cache-v02.jsonl"))
    hybrid.add_argument("--corpus-cache")
    hybrid.add_argument("--workers", type=int, default=4)
    hybrid.add_argument("--min-confidence", type=float, default=0.85)
    hybrid.add_argument("--case-output", default=str(DEFAULT_OUTPUT_DIR / "cases.jsonl"))
    hybrid.add_argument(
        "--analysis-output", default=str(DEFAULT_OUTPUT_DIR / "analysis.json")
    )
    hybrid.add_argument("--split-seed", default="zeroadr-agentdojo-v122-step2i")
    hybrid.add_argument("--auto-calibrate", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command_name == "agent":
        return _run_agent(args)
    if args.command_name == "detector":
        return _run_detector(args)
    if args.command_name == "hybrid":
        return _run_hybrid(args)
    parser.print_help()
    return 0


def _add_corpus_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--attack", default="tool_knowledge")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--user-task", action="append", default=[])
    parser.add_argument("--injection-task", action="append", default=[])


def _run_agent(args: Any) -> int:
    try:
        config = resolve_llm_config(
            base_url=None,
            model=args.model,
            language=None,
            timeout=None,
            max_output_tokens=None,
            config_path=Path(args.llm_config),
        )
        result = run_agentdojo_benchmark(
            base_url=config.base_url,
            api_key=config.api_key,
            model=config.model,
            suite=args.suite,
            attack=args.attack,
            benchmark_version=args.benchmark_version,
            user_tasks=tuple(args.user_task),
            injection_tasks=tuple(args.injection_task),
            logdir=Path(args.logdir),
            force_rerun=args.force_rerun,
            enable_zeroadr=args.defense == "zeroadr",
        )
    except (AgentDojoBenchmarkError, AgentDojoUnavailableError, LLMConfigurationError, ValueError) as exc:
        return _print_error(exc, "agentdojo_error")
    return _print_result(result)


def _run_detector(args: Any) -> int:
    try:
        result = run_agentdojo_detector_benchmark(
            suite=args.suite,
            attack=args.attack,
            benchmark_version=args.benchmark_version,
            user_tasks=tuple(args.user_task),
            injection_tasks=tuple(args.injection_task),
        )
    except (AgentDojoBenchmarkError, AgentDojoUnavailableError, ValueError, KeyError) as exc:
        return _print_error(exc, "agentdojo_detector_error")
    return _print_result(result)


def _run_hybrid(args: Any) -> int:
    try:
        if not 0.0 <= args.min_confidence <= 1.0:
            raise ValueError("min-confidence must be between 0 and 1")
        config = resolve_llm_gate_config(config_path=Path(args.llm_config))
        result = run_agentdojo_hybrid_benchmark(
            base_url=config.base_url,
            api_key=config.api_key,
            model=config.model,
            timeout=config.timeout,
            max_output_tokens=config.max_output_tokens,
            suite=args.suite,
            attack=args.attack,
            benchmark_version=args.benchmark_version,
            user_tasks=tuple(args.user_task),
            injection_tasks=tuple(args.injection_task),
            cache_path=args.cache,
            corpus_path=args.corpus_cache,
            workers=args.workers,
            min_confidence=args.min_confidence,
            case_output_path=args.case_output,
            analysis_output_path=args.analysis_output,
            split_seed=args.split_seed,
            auto_calibrate=args.auto_calibrate,
        )
    except (
        AgentDojoBenchmarkError,
        AgentDojoUnavailableError,
        LLMConfigurationError,
        ValueError,
        KeyError,
    ) as exc:
        return _print_error(exc, "agentdojo_hybrid_error")
    return _print_result(result)


def _print_error(exc: Exception, default_code: str) -> int:
    code = getattr(exc, "code", default_code)
    print(
        json.dumps(
            {"ok": False, "error": {"code": code, "message": str(exc)}},
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 1


def _print_result(result: dict[str, Any]) -> int:
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0

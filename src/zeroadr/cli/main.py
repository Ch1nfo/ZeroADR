from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from zeroadr import __version__
from zeroadr.api.demo import seed_demo_database
from zeroadr.api.readonly import build_api_index, build_api_session
from zeroadr.api.server import create_api_server, validate_api_bind_host
from zeroadr.endpoint.agent import (
    DEFAULT_AGENT_STATUS_FILE,
    EndpointAgentConfig,
    read_agent_health,
    run_endpoint_agent,
)
from zeroadr.endpoint.collectors.linux import LinuxCollectorUnavailable, LinuxEbpfCollector
from zeroadr.endpoint.collectors.linux_bcc import parse_sensitive_path_prefixes
from zeroadr.endpoint.collectors.mock import MockEndpointCollector
from zeroadr.endpoint.contracts import EndpointValidationError
from zeroadr.endpoint.lite import ingest_endpoint_jsonl
from zeroadr.endpoint.tailer import tail_endpoint_jsonl
from zeroadr.gateway.stdio_proxy import build_proxy_parser, run_stdio_proxy
from zeroadr.hook.adapters import hook_event_from_client_payload
from zeroadr.hook.approval_wait import wait_for_approval_resolution
from zeroadr.hook.adapter import HookRuntime
from zeroadr.llm.config import (
    LLMConfigurationError,
    resolve_llm_config,
    resolve_llm_gate_config,
)
from zeroadr.llm.adjudication import build_llm_adjudicator
from zeroadr.llm.stage_review import build_stage_reviewer
from zeroadr.llm.calibration import (
    GateCalibrationError,
    build_gate_metrics,
    build_gate_readiness,
    compare_gate_runs,
    evaluate_gate_labels,
    export_gate_label_template,
)
from zeroadr.llm.dogfood import run_gate_dogfood
from zeroadr.llm.service import LLMTriageError, analyze_session
from zeroadr.policy.engine import PolicyEngine
from zeroadr.reconstruction.agent_bom import bom_from_sqlite, bom_from_trace
from zeroadr.reconstruction.evidence import evidence_from_context, evidence_from_trace
from zeroadr.reconstruction.session import reconstruct_from_sqlite, reconstruct_from_trace
from zeroadr.reconstruction.summary import summary_from_sqlite, summary_from_trace
from zeroadr.replay.runner import replay_trace
from zeroadr.storage.database import SQLiteStore
from zeroadr.storage.jsonl import write_event_jsonl


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="zeroadr")
    parser.add_argument("--version", action="store_true")
    subparsers = parser.add_subparsers(dest="command_name")
    proxy_parser = subparsers.add_parser("proxy")
    build_proxy_parser(proxy_parser)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("trace")
    replay_parser.add_argument("--policy", default="policies/default.yaml")
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("resource", choices=["sessions"])
    inspect_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    export_parser = subparsers.add_parser("export")
    export_parser.add_argument("resource", choices=["session"])
    export_parser.add_argument("session_id")
    export_parser.add_argument("--format", choices=["jsonl"], default="jsonl")
    export_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    export_parser.add_argument("--output")
    hook_parser = subparsers.add_parser("hook")
    hook_subparsers = hook_parser.add_subparsers(dest="hook_command_name")
    hook_decide_parser = hook_subparsers.add_parser("decide")
    hook_decide_parser.add_argument(
        "--client",
        choices=["generic", "claude-code", "codex"],
        default="generic",
    )
    hook_decide_parser.add_argument("--policy", default="policies/default.yaml")
    hook_decide_parser.add_argument("--trace", default=".zeroadr/traces/hooks.jsonl")
    hook_decide_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    hook_decide_parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    hook_wait_parser = hook_subparsers.add_parser("wait-approval")
    hook_wait_parser.add_argument("--approval-id", required=True)
    hook_wait_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    hook_wait_parser.add_argument("--timeout", type=float, default=300.0)
    hook_wait_parser.add_argument("--poll-interval", type=float, default=1.0)
    hook_decide_wait_parser = hook_subparsers.add_parser("decide-and-wait")
    hook_decide_wait_parser.add_argument(
        "--client",
        choices=["generic", "claude-code", "codex"],
        default="generic",
    )
    hook_decide_wait_parser.add_argument("--policy", default="policies/default.yaml")
    hook_decide_wait_parser.add_argument("--trace", default=".zeroadr/traces/hooks.jsonl")
    hook_decide_wait_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    hook_decide_wait_parser.add_argument("--timeout", type=float, default=300.0)
    hook_decide_wait_parser.add_argument("--poll-interval", type=float, default=1.0)
    hook_decide_wait_parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    session_parser = subparsers.add_parser("session")
    session_subparsers = session_parser.add_subparsers(dest="session_command_name")
    reconstruct_parser = session_subparsers.add_parser("reconstruct")
    reconstruct_parser.add_argument("session_id", nargs="?")
    reconstruct_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    reconstruct_parser.add_argument("--trace")
    evidence_parser = session_subparsers.add_parser("evidence")
    evidence_parser.add_argument("session_id", nargs="?")
    evidence_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    evidence_parser.add_argument("--trace")
    evidence_parser.add_argument("--finding-id")
    evidence_parser.add_argument("--rule-id")
    summary_parser = session_subparsers.add_parser("summary")
    summary_parser.add_argument("session_id", nargs="?")
    summary_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    summary_parser.add_argument("--trace")
    bom_parser = session_subparsers.add_parser("bom")
    bom_parser.add_argument("session_id", nargs="?")
    bom_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    bom_parser.add_argument("--trace")
    analyze_parser = subparsers.add_parser("analyze")
    analyze_subparsers = analyze_parser.add_subparsers(dest="analyze_command_name")
    analyze_session_parser = analyze_subparsers.add_parser("session")
    analyze_session_parser.add_argument("session_id")
    analyze_session_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    analyze_session_parser.add_argument("--base-url")
    analyze_session_parser.add_argument("--model")
    analyze_session_parser.add_argument("--language", choices=["zh", "en"])
    analyze_session_parser.add_argument("--timeout", type=float)
    analyze_session_parser.add_argument("--max-output-tokens", type=int)
    analyze_session_parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    gate_parser = subparsers.add_parser("gate")
    gate_subparsers = gate_parser.add_subparsers(dest="gate_command_name")
    gate_metrics_parser = gate_subparsers.add_parser("metrics")
    gate_metrics_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    gate_metrics_parser.add_argument("--session-id")
    gate_metrics_parser.add_argument("--confidence-threshold", type=float, default=0.85)
    gate_evaluate_parser = gate_subparsers.add_parser("evaluate")
    gate_evaluate_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    gate_evaluate_parser.add_argument("--labels", required=True)
    gate_evaluate_parser.add_argument("--threshold", type=float, default=0.85)
    gate_labels_parser = gate_subparsers.add_parser("labels")
    gate_labels_subparsers = gate_labels_parser.add_subparsers(
        dest="gate_labels_command_name"
    )
    gate_labels_export_parser = gate_labels_subparsers.add_parser("export")
    gate_labels_export_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    gate_labels_export_parser.add_argument("--output", required=True)
    gate_labels_export_parser.add_argument("--session-id")
    gate_readiness_parser = gate_subparsers.add_parser("readiness")
    gate_readiness_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    gate_readiness_parser.add_argument("--labels", required=True)
    gate_readiness_parser.add_argument("--threshold", type=float, default=0.85)
    gate_readiness_parser.add_argument("--min-labeled-count", type=int, default=40)
    gate_readiness_parser.add_argument("--min-completion-rate", type=float, default=0.95)
    gate_readiness_parser.add_argument("--max-invalid-output-rate", type=float, default=0.01)
    gate_readiness_parser.add_argument("--max-p95-latency-ms", type=int, default=8000)
    gate_readiness_parser.add_argument("--max-false-negative-rate", type=float, default=0.02)
    gate_readiness_parser.add_argument("--max-false-positive-rate", type=float, default=0.05)
    gate_readiness_parser.add_argument("--max-review-rate", type=float, default=0.10)
    gate_dogfood_parser = gate_subparsers.add_parser("dogfood")
    gate_dogfood_parser.add_argument(
        "--cases",
        default="examples/llm/gate-dogfood-v01.jsonl",
    )
    gate_dogfood_parser.add_argument("--db", default=".zeroadr/gate-dogfood.sqlite")
    gate_dogfood_parser.add_argument("--policy", default="policies/llm-gate-shadow.yaml")
    gate_dogfood_parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    gate_dogfood_parser.add_argument(
        "--labels-output",
        default=".zeroadr/gate-dogfood-labels.jsonl",
    )
    gate_dogfood_parser.add_argument("--trace")
    gate_dogfood_parser.add_argument("--limit", type=int)
    gate_compare_parser = gate_subparsers.add_parser("compare")
    gate_compare_parser.add_argument("--baseline-db", required=True)
    gate_compare_parser.add_argument("--baseline-labels", required=True)
    gate_compare_parser.add_argument("--candidate-db", required=True)
    gate_compare_parser.add_argument("--candidate-labels", required=True)
    gate_compare_parser.add_argument("--threshold", type=float, default=0.85)
    api_parser = subparsers.add_parser("api")
    api_subparsers = api_parser.add_subparsers(dest="api_command_name")
    api_dump_parser = api_subparsers.add_parser("dump")
    api_dump_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    api_session_parser = api_subparsers.add_parser("session")
    api_session_parser.add_argument("session_id")
    api_session_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    api_seed_demo_parser = api_subparsers.add_parser("seed-demo")
    api_seed_demo_parser.add_argument("--db", default=".zeroadr/console-demo.sqlite")
    api_demo_parser = api_subparsers.add_parser("demo")
    api_demo_parser.add_argument("--db", default=".zeroadr/console-demo.sqlite")
    api_demo_parser.add_argument("--host", default="127.0.0.1")
    api_demo_parser.add_argument("--port", type=int, default=8765)
    api_demo_parser.add_argument("--allow-insecure-non-loopback", action="store_true")
    api_demo_parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    api_serve_parser = api_subparsers.add_parser("serve")
    api_serve_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    api_serve_parser.add_argument("--host", default="127.0.0.1")
    api_serve_parser.add_argument("--port", type=int, default=8765)
    api_serve_parser.add_argument("--agent-status-file")
    api_serve_parser.add_argument("--trace")
    api_serve_parser.add_argument("--approval-max-age", type=float, default=300.0)
    api_serve_parser.add_argument("--allow-insecure-non-loopback", action="store_true")
    api_serve_parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    endpoint_parser = subparsers.add_parser("endpoint")
    endpoint_subparsers = endpoint_parser.add_subparsers(dest="endpoint_command_name")
    endpoint_ingest_parser = endpoint_subparsers.add_parser("ingest")
    endpoint_ingest_parser.add_argument("--input", required=True)
    endpoint_ingest_parser.add_argument("--trace", default=".zeroadr/traces/endpoint.jsonl")
    endpoint_ingest_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    endpoint_ingest_parser.add_argument("--strict", action="store_true")
    endpoint_tail_parser = endpoint_subparsers.add_parser("tail")
    endpoint_tail_parser.add_argument("--input", required=True)
    endpoint_tail_parser.add_argument("--trace", default=".zeroadr/traces/endpoint.jsonl")
    endpoint_tail_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    endpoint_tail_parser.add_argument("--checkpoint-file")
    endpoint_tail_parser.add_argument("--stop-after-idle", type=float)
    endpoint_tail_parser.add_argument("--poll-interval", type=float, default=0.1)
    endpoint_tail_parser.add_argument("--strict", action="store_true")
    endpoint_collect_parser = endpoint_subparsers.add_parser("collect")
    endpoint_collect_parser.add_argument("--collector", choices=["mock", "linux"], required=True)
    endpoint_collect_parser.add_argument("--output", required=True)
    endpoint_collect_parser.add_argument("--limit", type=int)
    endpoint_collect_parser.add_argument("--session-id")
    endpoint_collect_parser.add_argument("--host-id")
    endpoint_collect_parser.add_argument("--trace")
    endpoint_collect_parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    endpoint_collect_parser.add_argument("--strict-ingest", action="store_true")
    endpoint_agent_parser = endpoint_subparsers.add_parser("agent")
    endpoint_agent_parser.add_argument("--collector", choices=["mock", "linux"], required=True)
    endpoint_agent_parser.add_argument("--output", required=True)
    endpoint_agent_parser.add_argument("--status-file", default=str(DEFAULT_AGENT_STATUS_FILE))
    endpoint_agent_parser.add_argument("--pid-file")
    endpoint_agent_parser.add_argument("--limit", type=int)
    endpoint_agent_parser.add_argument("--session-id", default="sess_endpoint_agent")
    endpoint_agent_parser.add_argument("--host-id")
    endpoint_agent_parser.add_argument("--trace")
    endpoint_agent_parser.add_argument("--db")
    endpoint_agent_parser.add_argument("--stop-after-idle", type=float)
    endpoint_agent_parser.add_argument("--poll-interval", type=float, default=0.1)
    endpoint_agent_parser.add_argument("--strict-ingest", action="store_true")
    endpoint_agent_parser.add_argument("--rotate-bytes", type=int)
    endpoint_agent_parser.add_argument("--max-rotated-files", type=int, default=5)
    endpoint_agent_parser.add_argument("--max-output-bytes", type=int)
    endpoint_agent_parser.add_argument("--write-retry-count", type=int, default=0)
    endpoint_agent_parser.add_argument("--write-retry-delay", type=float, default=0.05)
    endpoint_agent_parser.add_argument("--heartbeat-interval", type=float)
    endpoint_agent_parser.add_argument("--sensitive-path-prefixes")
    endpoint_agent_parser.add_argument("--bcc-poll-timeout-ms", type=int, default=100)
    endpoint_agent_parser.add_argument("--bcc-max-queue", type=int, default=4096)
    endpoint_status_parser = endpoint_subparsers.add_parser("status")
    endpoint_status_parser.add_argument("--status-file", required=True)
    endpoint_status_parser.add_argument("--stale-after", type=float)
    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0
    if args.command_name == "proxy":
        command = list(args.command)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            parser.error("proxy requires a command after --")
        return asyncio.run(
            run_stdio_proxy(
                command,
                policy_path=Path(args.policy),
                trace_path=Path(args.trace),
                db_path=Path(args.db),
                approval_timeout=args.approval_timeout,
                approval_poll_interval=args.approval_poll_interval,
                llm_config_path=Path(args.llm_config),
            )
        )
    if args.command_name == "replay":
        trace = replay_trace(Path(args.trace), PolicyEngine.from_file(Path(args.policy)))
        _print_trace_summary(trace)
        return 0
    if args.command_name == "inspect":
        store = SQLiteStore(Path(args.db))
        for session_id in store.list_sessions():
            print(session_id)
        return 0
    if args.command_name == "export":
        store = SQLiteStore(Path(args.db))
        events = store.events_for_session(args.session_id)
        if args.output:
            output = Path(args.output)
            if output.exists():
                output.unlink()
            for event in events:
                write_event_jsonl(output, event)
        else:
            for event in events:
                print(event.model_dump_json())
        return 0
    if args.command_name == "hook":
        if args.hook_command_name == "decide":
            return _run_hook_decide(args)
        if args.hook_command_name == "wait-approval":
            return _run_hook_wait_approval(args)
        if args.hook_command_name == "decide-and-wait":
            return _run_hook_decide_and_wait(args)
        parser.error("hook requires a subcommand")
    if args.command_name == "session":
        if args.session_command_name == "reconstruct":
            return _run_session_reconstruct(args)
        if args.session_command_name == "evidence":
            return _run_session_evidence(args)
        if args.session_command_name == "summary":
            return _run_session_summary(args)
        if args.session_command_name == "bom":
            return _run_session_bom(args)
        parser.error("session requires a subcommand")
    if args.command_name == "analyze":
        if args.analyze_command_name == "session":
            return _run_analyze_session(args)
        parser.error("analyze requires a subcommand")
    if args.command_name == "gate":
        if args.gate_command_name == "metrics":
            return _run_gate_metrics(args)
        if args.gate_command_name == "evaluate":
            return _run_gate_evaluate(args)
        if args.gate_command_name == "labels":
            if args.gate_labels_command_name == "export":
                return _run_gate_labels_export(args)
            parser.error("gate labels requires a subcommand")
        if args.gate_command_name == "readiness":
            return _run_gate_readiness(args)
        if args.gate_command_name == "dogfood":
            return _run_gate_dogfood(args)
        if args.gate_command_name == "compare":
            return _run_gate_compare(args)
        parser.error("gate requires a subcommand")
    if args.command_name == "api":
        if args.api_command_name == "dump":
            return _run_api_dump(args)
        if args.api_command_name == "session":
            return _run_api_session(args)
        if args.api_command_name == "seed-demo":
            return _run_api_seed_demo(args)
        if args.api_command_name == "demo":
            return _run_api_demo(args)
        if args.api_command_name == "serve":
            return _run_api_serve(args)
        parser.error("api requires a subcommand")
    if args.command_name == "endpoint":
        if args.endpoint_command_name == "ingest":
            return _run_endpoint_ingest(args)
        if args.endpoint_command_name == "tail":
            return _run_endpoint_tail(args)
        if args.endpoint_command_name == "collect":
            return _run_endpoint_collect(args)
        if args.endpoint_command_name == "agent":
            return _run_endpoint_agent(args)
        if args.endpoint_command_name == "status":
            return _run_endpoint_status(args)
        parser.error("endpoint requires a subcommand")
    parser.print_help()
    return 0


def _run_hook_decide(args: Any) -> int:
    payload = json.loads(sys.stdin.read())
    if not isinstance(payload, dict):
        raise ValueError("hook decide expects a JSON object on stdin")
    policy_engine = PolicyEngine.from_file(Path(args.policy))
    runtime = HookRuntime(
        policy_engine=policy_engine,
        trace_path=Path(args.trace),
        db_path=Path(args.db),
        adjudicator=(
            build_llm_adjudicator(Path(args.llm_config))
            if policy_engine.has_llm_adjudication()
            else None
        ),
        stage_reviewer=(
            build_stage_reviewer(Path(args.llm_config))
            if policy_engine.has_stage_review()
            else None
        ),
    )
    response = runtime.handle(hook_event_from_client_payload(payload, client=args.client))
    print(response.model_dump_json())
    return 0


def _run_hook_wait_approval(args: Any) -> int:
    try:
        result = wait_for_approval_resolution(
            Path(args.db),
            args.approval_id,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
            trace_path=Path(args.trace) if getattr(args, "trace", None) else None,
        )
    except KeyError:
        print(json.dumps({"approval_id": args.approval_id, "status": "not_found", "effective_action": "block"}))
        return 1
    print(json.dumps(result))
    if result["status"] in {"expired", "not_found", "denied"}:
        return 1
    return 0


def _run_hook_decide_and_wait(args: Any) -> int:
    payload = json.loads(sys.stdin.read())
    if not isinstance(payload, dict):
        raise ValueError("hook decide-and-wait expects a JSON object on stdin")
    policy_engine = PolicyEngine.from_file(Path(args.policy))
    runtime = HookRuntime(
        policy_engine=policy_engine,
        trace_path=Path(args.trace),
        db_path=Path(args.db),
        adjudicator=(
            build_llm_adjudicator(Path(args.llm_config))
            if policy_engine.has_llm_adjudication()
            else None
        ),
        stage_reviewer=(
            build_stage_reviewer(Path(args.llm_config))
            if policy_engine.has_stage_review()
            else None
        ),
    )
    response = runtime.handle(hook_event_from_client_payload(payload, client=args.client))
    result = response.model_dump(mode="json")
    if response.action == "require_approval" and response.approval_id:
        wait_result = wait_for_approval_resolution(
            Path(args.db),
            response.approval_id,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
            trace_path=Path(args.trace),
        )
        result["wait"] = wait_result
        print(json.dumps(result))
        if wait_result.get("effective_action") == "block":
            return 1
        return 0
    print(json.dumps(result))
    return 0


def _run_session_reconstruct(args: Any) -> int:
    if args.trace:
        context = reconstruct_from_trace(Path(args.trace))
    else:
        if not args.session_id:
            raise ValueError("session reconstruct requires a session_id unless --trace is provided")
        context = reconstruct_from_sqlite(str(args.session_id), Path(args.db))
    print(json.dumps(context, indent=2, sort_keys=True))
    return 0


def _run_session_evidence(args: Any) -> int:
    if args.trace:
        evidence = evidence_from_trace(
            Path(args.trace),
            finding_id=args.finding_id,
            rule_id=args.rule_id,
        )
    else:
        if not args.session_id:
            raise ValueError("session evidence requires a session_id unless --trace is provided")
        evidence = evidence_from_context(
            reconstruct_from_sqlite(str(args.session_id), Path(args.db)),
            finding_id=args.finding_id,
            rule_id=args.rule_id,
        )
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


def _run_session_summary(args: Any) -> int:
    if args.trace:
        summary = summary_from_trace(Path(args.trace))
    else:
        if not args.session_id:
            raise ValueError("session summary requires a session_id unless --trace is provided")
        summary = summary_from_sqlite(str(args.session_id), Path(args.db))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _run_session_bom(args: Any) -> int:
    if args.trace:
        bom = bom_from_trace(Path(args.trace))
    else:
        if not args.session_id:
            raise ValueError("session bom requires a session_id unless --trace is provided")
        bom = bom_from_sqlite(str(args.session_id), Path(args.db))
    print(json.dumps(bom, indent=2, sort_keys=True))
    return 0


def _run_analyze_session(args: Any) -> int:
    try:
        config = resolve_llm_config(
            base_url=args.base_url,
            model=args.model,
            language=args.language,
            timeout=args.timeout,
            max_output_tokens=args.max_output_tokens,
            config_path=Path(getattr(args, "llm_config", ".zeroadr/llm-config.json")),
        )
        analysis = analyze_session(
            str(args.session_id),
            db_path=Path(args.db),
            config=config,
        )
    except (LLMConfigurationError, LLMTriageError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": exc.code,
                        "message": str(exc),
                    },
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(analysis.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _run_gate_metrics(args: Any) -> int:
    try:
        payload = build_gate_metrics(
            Path(args.db),
            session_id=args.session_id,
            confidence_threshold=args.confidence_threshold,
        )
    except GateCalibrationError as exc:
        return _print_gate_error(exc)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _run_gate_evaluate(args: Any) -> int:
    try:
        payload = evaluate_gate_labels(
            Path(args.db),
            Path(args.labels),
            threshold=args.threshold,
        )
    except GateCalibrationError as exc:
        return _print_gate_error(exc)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _run_gate_labels_export(args: Any) -> int:
    try:
        payload = export_gate_label_template(
            Path(args.db),
            Path(args.output),
            session_id=args.session_id,
        )
    except GateCalibrationError as exc:
        return _print_gate_error(exc)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _run_gate_readiness(args: Any) -> int:
    try:
        payload = build_gate_readiness(
            Path(args.db),
            Path(args.labels),
            threshold=args.threshold,
            min_labeled_count=args.min_labeled_count,
            min_completion_rate=args.min_completion_rate,
            max_invalid_output_rate=args.max_invalid_output_rate,
            max_p95_latency_ms=args.max_p95_latency_ms,
            max_false_negative_rate=args.max_false_negative_rate,
            max_false_positive_rate=args.max_false_positive_rate,
            max_review_rate=args.max_review_rate,
        )
    except GateCalibrationError as exc:
        return _print_gate_error(exc)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload["ready"] else 1


def _run_gate_dogfood(args: Any) -> int:
    try:
        config_path = Path(args.llm_config)
        resolve_llm_gate_config(config_path=config_path)
        payload = run_gate_dogfood(
            cases_path=Path(args.cases),
            db_path=Path(args.db),
            policy_path=Path(args.policy),
            labels_output=Path(args.labels_output),
            adjudicator=build_llm_adjudicator(config_path),
            trace_path=Path(args.trace) if args.trace else None,
            limit=args.limit,
        )
    except (GateCalibrationError, LLMConfigurationError) as exc:
        if isinstance(exc, GateCalibrationError):
            return _print_gate_error(exc)
        print(
            json.dumps(
                {"ok": False, "error": {"code": exc.code, "message": str(exc)}},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _run_gate_compare(args: Any) -> int:
    try:
        payload = compare_gate_runs(
            baseline_db=Path(args.baseline_db),
            baseline_labels=Path(args.baseline_labels),
            candidate_db=Path(args.candidate_db),
            candidate_labels=Path(args.candidate_labels),
            threshold=args.threshold,
        )
    except GateCalibrationError as exc:
        return _print_gate_error(exc)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _print_gate_error(exc: GateCalibrationError) -> int:
    print(
        json.dumps(
            {"ok": False, "error": {"code": exc.code, "message": str(exc)}},
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 1


def _run_api_dump(args: Any) -> int:
    print(json.dumps(build_api_index(Path(args.db)), indent=2, sort_keys=True))
    return 0


def _run_api_session(args: Any) -> int:
    print(json.dumps(build_api_session(str(args.session_id), Path(args.db)), indent=2, sort_keys=True))
    return 0


def _run_api_seed_demo(args: Any) -> int:
    print(json.dumps(seed_demo_database(Path(args.db)), indent=2, sort_keys=True))
    return 0


def _run_api_demo(args: Any) -> int:
    validate_api_bind_host(
        args.host,
        allow_insecure_non_loopback=getattr(args, "allow_insecure_non_loopback", False),
    )
    seed_result = seed_demo_database(Path(args.db))
    server_kwargs: dict[str, Any] = {
        "db_path": Path(args.db),
        "host": args.host,
        "port": args.port,
    }
    if getattr(args, "llm_config", None):
        server_kwargs["llm_config_path"] = Path(args.llm_config)
    server = create_api_server(**server_kwargs)
    host = str(server.server_address[0])
    port = int(server.server_address[1])
    print(
        json.dumps(
            {
                "api_version": "0.1",
                "db": str(Path(args.db)),
                "host": host,
                "port": port,
                "session_count": seed_result["session_count"],
                "url": f"http://{host}:{port}/console",
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def _run_api_serve(args: Any) -> int:
    validate_api_bind_host(
        args.host,
        allow_insecure_non_loopback=getattr(args, "allow_insecure_non_loopback", False),
    )
    agent_status_path = Path(args.agent_status_file) if args.agent_status_file else None
    server_kwargs: dict[str, Any] = {
        "db_path": Path(args.db),
        "host": args.host,
        "port": args.port,
        "agent_status_path": agent_status_path,
        "trace_path": Path(args.trace) if args.trace else None,
        "approval_max_age_seconds": args.approval_max_age,
    }
    if getattr(args, "llm_config", None):
        server_kwargs["llm_config_path"] = Path(args.llm_config)
    server = create_api_server(**server_kwargs)
    host = str(server.server_address[0])
    port = int(server.server_address[1])
    print(
        json.dumps(
            {
                "api_version": "0.1",
                "db": str(Path(args.db)),
                "host": host,
                "port": port,
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def _run_endpoint_ingest(args: Any) -> int:
    try:
        result = ingest_endpoint_jsonl(
            Path(args.input),
            trace_path=Path(args.trace),
            db_path=Path(args.db),
            strict=args.strict,
        )
    except EndpointValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run_endpoint_tail(args: Any) -> int:
    try:
        result = tail_endpoint_jsonl(
            Path(args.input),
            trace_path=Path(args.trace),
            db_path=Path(args.db),
            checkpoint_path=Path(args.checkpoint_file) if args.checkpoint_file else None,
            stop_after_idle=args.stop_after_idle,
            poll_interval=args.poll_interval,
            strict=args.strict,
        )
    except EndpointValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run_endpoint_collect(args: Any) -> int:
    collector = _build_endpoint_collector(
        args.collector,
        session_id=args.session_id,
        host_id=args.host_id,
    )
    collect_result = collector.write_jsonl(Path(args.output), limit=args.limit)
    result: dict[str, Any] = dict(collect_result)
    if args.trace:
        try:
            ingest_result = ingest_endpoint_jsonl(
                Path(args.output),
                trace_path=Path(args.trace),
                db_path=Path(args.db),
                strict=args.strict_ingest,
            )
        except EndpointValidationError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        result.update(ingest_result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run_endpoint_agent(args: Any) -> int:
    try:
        result = run_endpoint_agent(
            EndpointAgentConfig(
                collector=args.collector,
                output_path=Path(args.output),
                status_path=Path(args.status_file),
                pid_path=Path(args.pid_file) if args.pid_file else None,
                trace_path=Path(args.trace) if args.trace else None,
                db_path=Path(args.db) if args.db else None,
                session_id=args.session_id,
                host_id=args.host_id,
                limit=args.limit,
                stop_after_idle=args.stop_after_idle,
                poll_interval=args.poll_interval,
                strict_ingest=args.strict_ingest,
                rotate_bytes=args.rotate_bytes,
                max_rotated_files=args.max_rotated_files,
                max_output_bytes=args.max_output_bytes,
                write_retry_count=args.write_retry_count,
                write_retry_delay=args.write_retry_delay,
                heartbeat_interval=args.heartbeat_interval,
                sensitive_path_prefixes=parse_sensitive_path_prefixes(args.sensitive_path_prefixes),
                bcc_poll_timeout_ms=args.bcc_poll_timeout_ms,
                bcc_max_queue=args.bcc_max_queue,
            )
        )
    except LinuxCollectorUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (EndpointValidationError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run_endpoint_status(args: Any) -> int:
    result = read_agent_health(Path(args.status_file), stale_after=args.stale_after)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["healthy"] else 1


def _build_endpoint_collector(
    name: str,
    *,
    session_id: str | None = None,
    host_id: str | None = None,
) -> MockEndpointCollector | LinuxEbpfCollector:
    if name == "mock":
        if session_id or host_id:
            return MockEndpointCollector(
                session_id=session_id or "sess_mock_collector",
                host_id=host_id or "host_mock",
            )
        return MockEndpointCollector()
    if name == "linux":
        collector = LinuxEbpfCollector(
            session_id=session_id or "sess_linux_bcc",
            host_id=host_id,
        )
        try:
            collector.check_available()
        except LinuxCollectorUnavailable as exc:
            raise SystemExit(str(exc)) from exc
        return collector
    raise ValueError(f"unknown endpoint collector: {name}")


def _print_trace_summary(trace: object) -> None:
    session_id = getattr(trace, "session_id")
    events = getattr(trace, "events")
    findings = getattr(trace, "findings")
    decisions = getattr(trace, "policy_decisions")
    print(f"ZeroADR Session: {session_id}")
    print(f"Events: {len(events)}")
    findings_by_event: dict[str, list[Any]] = {}
    for finding in findings:
        for event_id in finding.event_ids:
            findings_by_event.setdefault(event_id, []).append(finding)
    decisions_by_event = {decision.event_id: decision for decision in decisions}
    printed_decisions: set[str] = set()
    for event in events:
        if event.event_type != "tool.call.requested":
            continue
        event_findings = findings_by_event.get(event.event_id, [])
        decision = decisions_by_event.get(event.event_id)
        printed_decisions.update(
            finding.finding_id for finding in event_findings if decision is not None
        )
        if not event_findings:
            action = decision.action.upper() if decision is not None else "ALLOW"
            print(f"[{action}] {event.capability or 'unknown'}")
            print(f"Target: {_event_target(event)}")
            if decision is not None:
                _print_decision(decision)
            continue
        for finding in event_findings:
            print(f"[{finding.severity.upper()}] {finding.title}")
            print(f"Rule: {finding.rule_id}")
            print(f"Target: {finding.target}")
            if decision is not None:
                _print_decision(decision)
    for decision in decisions:
        if decision.finding_ids and all(
            finding_id in printed_decisions for finding_id in decision.finding_ids
        ):
            continue
        if decision.event_id in decisions_by_event and not decision.finding_ids:
            continue
        _print_decision(decision)


def _print_decision(decision: Any) -> None:
    print(f"Decision: {decision.action}")
    print(f"Policy: {decision.policy_id or 'default'}")
    if decision.finding_ids:
        print(f"Findings: {', '.join(decision.finding_ids)}")
    print(f"Reason: {decision.reason}")


def _event_target(event: Any) -> str:
    arguments = event.arguments if isinstance(event.arguments, dict) else {}
    for key in ("path", "file", "filename", "command", "cmd", "url", "uri", "endpoint"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    return event.tool_name or "unknown"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

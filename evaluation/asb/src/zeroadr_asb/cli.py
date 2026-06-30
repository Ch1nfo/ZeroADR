from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from zeroadr_asb.analysis import analyze_results
from zeroadr_asb.benchmark import run_benchmark, run_concurrency_sweep
from zeroadr_asb.manifest import ASB_COMMIT, ASB_SEED, build_manifest, write_manifest
from zeroadr_asb.source import prepare_asb_source, verify_asb_source


DEFAULT_ROOT = Path(".zeroadr/evaluations/asb/official-v2")
DEFAULT_ASB_ROOT = Path(".zeroadr/vendor/asb")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zeroadr-asb")
    commands = parser.add_subparsers(dest="command_name")
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--asb-root", default=str(DEFAULT_ASB_ROOT))
    prepare.add_argument("--commit", default=ASB_COMMIT)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--asb-root", default=str(DEFAULT_ASB_ROOT))
    manifest.add_argument("--attack-cases", type=int, default=100)
    manifest.add_argument("--paired-clean", action=argparse.BooleanOptionalAction, default=True)
    manifest.add_argument("--seed", default=ASB_SEED)
    manifest.add_argument("--output", default=str(DEFAULT_ROOT / "manifest-asb-100-v2.jsonl"))
    run = commands.add_parser("run")
    _add_run_args(run)
    run.add_argument("--asb-root", default=str(DEFAULT_ASB_ROOT))
    analyze = commands.add_parser("analyze")
    analyze.add_argument("--cases", default=str(DEFAULT_ROOT / "cases.jsonl"))
    analyze.add_argument("--output", default=str(DEFAULT_ROOT / "analysis.json"))
    benchmark = commands.add_parser("benchmark")
    _add_run_args(benchmark)
    benchmark.add_argument("--asb-root", default=str(DEFAULT_ASB_ROOT))
    sweep = commands.add_parser("sweep")
    _add_run_args(sweep)
    sweep.add_argument("--asb-root", default=str(DEFAULT_ASB_ROOT))
    sweep.set_defaults(dry_run=True)
    return parser


def _add_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--arms", default="baseline,rules,hybrid")
    parser.add_argument("--manifest", default=str(DEFAULT_ROOT / "manifest-asb-100-v2.jsonl"))
    parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-dir", default=str(DEFAULT_ROOT / "formal"))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command_name == "manifest":
            verify_asb_source(Path(args.asb_root))
            cases = build_manifest(
                Path(args.asb_root),
                attack_cases=args.attack_cases,
                paired_clean=args.paired_clean,
                seed=args.seed,
            )
            write_manifest(Path(args.output), cases)
            return _print({"ok": True, "case_count": len(cases), "output": args.output})
        if args.command_name == "prepare":
            return _print(
                {"ok": True, **prepare_asb_source(Path(args.asb_root), args.commit)}
            )
        if args.command_name in {"run", "benchmark", "sweep"}:
            asb_root = Path(getattr(args, "asb_root", DEFAULT_ASB_ROOT))
            verify_asb_source(asb_root)
            arms = tuple(item.strip() for item in args.arms.split(",") if item.strip())
            runner = run_concurrency_sweep if args.command_name == "sweep" else run_benchmark
            result = runner(
                asb_root=asb_root,
                manifest_path=Path(args.manifest),
                output_dir=Path(args.output_dir),
                arms=arms,
                llm_config_path=Path(args.llm_config),
                **({} if args.command_name == "sweep" else {"workers": args.workers}),
                resume=args.resume,
                dry_run=args.dry_run,
            )
            return _print(result)
        if args.command_name == "analyze":
            rows = [
                json.loads(line)
                for line in Path(args.cases).read_text(encoding="utf-8").splitlines()
                if line
            ]
            report = analyze_results(rows)
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            output.write_text(
                json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            output.chmod(0o600)
            return _print({"ok": True, "output": str(output), "analysis": report})
        if args.command_name is None:
            parser.print_help()
            return 0
        return _print_error(NotImplementedError(f"{args.command_name} is not implemented."))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _print_error(exc)


def _print(result: dict[str, Any]) -> int:
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _print_error(exc: Exception) -> int:
    print(
        json.dumps(
            {
                "ok": False,
                "error": {
                    "code": getattr(exc, "code", "asb_error"),
                    "message": str(exc),
                },
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 1

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from zeroadr.core.events import new_event
from zeroadr.detection.prompt_injection import PromptInjectionDetector


class AgentDojoUnavailableError(RuntimeError):
    pass


class AgentDojoBenchmarkError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class AgentDojoDetectorCase:
    case_id: str
    label: bool
    suite: str
    attack: str
    user_task_id: str
    injection_task_id: str
    tool_name: str
    text: str


class ZeroADRPromptInjectionClassifier:
    def __init__(self) -> None:
        self.detector = PromptInjectionDetector()

    def detect(self, tool_output: str) -> tuple[bool, float]:
        event = new_event(
            event_type="tool.call.completed",
            source_type="replay",
            session_id="agentdojo",
            capability="tool.result",
            result={"content": [{"text": tool_output}]},
        )
        findings = self.detector.detect(event)
        if not findings:
            return False, 0.0
        return True, max(finding.confidence for finding in findings)


def summarize_detector_predictions(
    *, labels: list[bool], predictions: list[bool]
) -> dict[str, int | float]:
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must have the same length")
    true_positive = sum(label and prediction for label, prediction in zip(labels, predictions))
    false_positive = sum(not label and prediction for label, prediction in zip(labels, predictions))
    true_negative = sum(not label and not prediction for label, prediction in zip(labels, predictions))
    false_negative = sum(label and not prediction for label, prediction in zip(labels, predictions))
    positive_count = true_positive + false_negative
    negative_count = true_negative + false_positive
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, positive_count)
    return {
        "case_count": len(labels),
        "positive_count": positive_count,
        "negative_count": negative_count,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "recall": recall,
        "precision": precision,
        "accuracy": _ratio(true_positive + true_negative, len(labels)),
        "f1": _ratio(2 * precision * recall, precision + recall),
        "false_positive_rate": _ratio(false_positive, negative_count),
    }


def evaluate_agentdojo_detector(
    cases: list[AgentDojoDetectorCase],
    *,
    classifier: ZeroADRPromptInjectionClassifier | None = None,
) -> dict[str, Any]:
    active_classifier = classifier or ZeroADRPromptInjectionClassifier()
    predictions = [active_classifier.detect(case.text)[0] for case in cases]
    return {
        "benchmark": "agentdojo",
        "evaluation": "detector_only",
        "blocking_semantics": "detector_hit_is_block",
        "metrics": summarize_detector_predictions(
            labels=[case.label for case in cases], predictions=predictions
        ),
    }


def build_agentdojo_detector_corpus(
    *,
    suite: str = "workspace",
    attack: str = "tool_knowledge",
    benchmark_version: str = "v1.2.2",
    user_tasks: tuple[str, ...] = (),
    injection_tasks: tuple[str, ...] = (),
) -> list[AgentDojoDetectorCase]:
    dependencies = _require_agentdojo()
    task_suite = dependencies.get_suite(benchmark_version, suite)
    _validate_task_ids(task_suite, user_tasks, injection_tasks)
    target_pipeline = SimpleNamespace(name="gpt-4o-2024-05-13")
    benchmark_attack = dependencies.load_attack(attack, task_suite, target_pipeline)
    selected_users = user_tasks or tuple(sorted(task_suite.user_tasks))
    selected_injections = injection_tasks or tuple(sorted(task_suite.injection_tasks))
    clean_outputs: dict[str, list[tuple[str, str]]] = {}
    cases: list[AgentDojoDetectorCase] = []

    for user_task_id in selected_users:
        user_task = task_suite.user_tasks[user_task_id]
        clean_outputs[user_task_id] = _ground_truth_tool_outputs(
            dependencies, task_suite, user_task, injections={}
        )
        for injection_task_id in selected_injections:
            injection_task = task_suite.injection_tasks[injection_task_id]
            injected_values = benchmark_attack.attack(user_task, injection_task)
            injected_outputs = _ground_truth_tool_outputs(
                dependencies, task_suite, user_task, injections=injected_values
            )
            for output_index, (tool_name, injected_text) in enumerate(injected_outputs):
                if output_index >= len(clean_outputs[user_task_id]):
                    raise AgentDojoBenchmarkError("Injected and clean tool outputs are not aligned.")
                clean_tool_name, clean_text = clean_outputs[user_task_id][output_index]
                if injected_text == clean_text:
                    continue
                pair_id = f"{user_task_id}:{injection_task_id}:{output_index}"
                cases.extend(
                    [
                        AgentDojoDetectorCase(
                            case_id=f"{pair_id}:injected",
                            label=True,
                            suite=suite,
                            attack=attack,
                            user_task_id=user_task_id,
                            injection_task_id=injection_task_id,
                            tool_name=tool_name,
                            text=injected_text,
                        ),
                        AgentDojoDetectorCase(
                            case_id=f"{pair_id}:clean",
                            label=False,
                            suite=suite,
                            attack=attack,
                            user_task_id=user_task_id,
                            injection_task_id=injection_task_id,
                            tool_name=clean_tool_name,
                            text=clean_text,
                        ),
                    ]
                )
    return cases


def run_agentdojo_detector_benchmark(
    *,
    suite: str = "workspace",
    attack: str = "tool_knowledge",
    benchmark_version: str = "v1.2.2",
    user_tasks: tuple[str, ...] = (),
    injection_tasks: tuple[str, ...] = (),
) -> dict[str, Any]:
    cases = build_agentdojo_detector_corpus(
        suite=suite,
        attack=attack,
        benchmark_version=benchmark_version,
        user_tasks=user_tasks,
        injection_tasks=injection_tasks,
    )
    report = evaluate_agentdojo_detector(cases)
    report.update(
        {
            "benchmark_version": benchmark_version,
            "suite": suite,
            "attack": attack,
            "pair_count": len(cases) // 2,
        }
    )
    return report


def _ground_truth_tool_outputs(
    dependencies: SimpleNamespace,
    task_suite: Any,
    user_task: Any,
    *,
    injections: dict[str, str],
) -> list[tuple[str, str]]:
    environment = task_suite.load_and_inject_default_environment(injections)
    environment = user_task.init_environment(environment)
    runtime = dependencies.FunctionsRuntime(task_suite.tools)
    pipeline = dependencies.GroundTruthPipeline(user_task)
    _, _, _, messages, _ = pipeline.query(user_task.PROMPT, runtime, environment)
    return [
        (
            message["tool_call"].function,
            dependencies.get_text_content_as_str(message["content"]),
        )
        for message in messages
        if message["role"] == "tool"
    ]


def build_agentdojo_pipeline(
    *,
    base_url: str,
    api_key: str,
    model: str,
    enable_zeroadr: bool = True,
) -> Any:
    dependencies = _require_agentdojo()
    classifier = ZeroADRPromptInjectionClassifier()
    dojo_detector_base: Any = dependencies.PromptInjectionDetector
    openai_llm_base: Any = dependencies.OpenAILLM

    class ZeroADRAgentDojoDefense(dojo_detector_base):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__(mode="message", raise_on_injection=False)

        def detect(self, tool_output: str) -> tuple[bool, float]:
            return classifier.detect(tool_output)

    class ZeroADROpenAICompatibleLLM(openai_llm_base):  # type: ignore[misc]
        def query(  # type: ignore[no-untyped-def]
            self,
            query,
            runtime,
            env=None,
            messages=(),
            extra_args=None,
        ):
            openai_messages = []
            for message in messages:
                converted = dict(dependencies.message_to_openai(message, self.model))
                if converted.get("role") == "developer":
                    converted["role"] = "system"
                openai_messages.append(converted)
            tools = [dependencies.function_to_openai(tool) for tool in runtime.functions.values()]
            completion = dependencies.chat_completion_request(
                self.client,
                self.model,
                openai_messages,
                tools,
                self.reasoning_effort,
                self.temperature,
            )
            output = dependencies.assistant_message_from_openai(completion.choices[0].message)
            return query, runtime, env, [*messages, output], extra_args or {}

    client = dependencies.openai.OpenAI(api_key=api_key, base_url=base_url)
    llm = ZeroADROpenAICompatibleLLM(client, model)
    pipeline = dependencies.AgentPipeline.from_config(
        dependencies.PipelineConfig(
            llm=llm,
            model_id=None,
            defense=None,
            system_message_name=None,
            system_message=None,
            tool_output_format=None,
        )
    )
    loop = list(pipeline.elements)[-1]
    if enable_zeroadr:
        loop.elements = [loop.elements[0], ZeroADRAgentDojoDefense(), *loop.elements[1:]]
    # AgentDojo 0.1.35's wheel omits openai-compatible from MODEL_NAMES.
    suffix = "zeroadr" if enable_zeroadr else "baseline"
    pipeline.name = f"local-{model}-{suffix}"
    return pipeline


def run_agentdojo_benchmark(
    *,
    base_url: str,
    api_key: str,
    model: str,
    suite: str = "workspace",
    attack: str = "tool_knowledge",
    benchmark_version: str = "v1.2.2",
    user_tasks: tuple[str, ...] = (),
    injection_tasks: tuple[str, ...] = (),
    logdir: Path = Path(".zeroadr/agentdojo-runs"),
    force_rerun: bool = False,
    enable_zeroadr: bool = True,
) -> dict[str, Any]:
    dependencies = _require_agentdojo()
    task_suite = dependencies.get_suite(benchmark_version, suite)
    _validate_task_ids(task_suite, user_tasks, injection_tasks)
    pipeline = build_agentdojo_pipeline(
        base_url=base_url,
        api_key=api_key,
        model=model,
        enable_zeroadr=enable_zeroadr,
    )
    benchmark_attack = dependencies.load_attack(attack, task_suite, pipeline)
    logdir.mkdir(parents=True, exist_ok=True)
    try:
        with dependencies.OutputLogger(str(logdir)):
            results = dependencies.benchmark_suite_with_injections(
                pipeline,
                task_suite,
                benchmark_attack,
                logdir=logdir,
                force_rerun=force_rerun,
                user_tasks=user_tasks or None,
                injection_tasks=injection_tasks or None,
                verbose=False,
                benchmark_version=benchmark_version,
            )
    except Exception as exc:
        raise AgentDojoBenchmarkError(
            f"AgentDojo benchmark failed with {type(exc).__name__}."
        ) from exc
    return summarize_agentdojo_results(
        results,
        suite=suite,
        attack=attack,
        benchmark_version=benchmark_version,
        pipeline_name=pipeline.name,
        logdir=logdir,
    )


def summarize_agentdojo_results(
    results: Mapping[str, Mapping[Any, bool]],
    *,
    suite: str,
    attack: str,
    benchmark_version: str,
    pipeline_name: str,
    logdir: Path | None = None,
) -> dict[str, Any]:
    utility = list(results["utility_results"].values())
    injection_success = list(results["security_results"].values())
    injection_utility = list(results["injection_tasks_utility_results"].values())
    attack_success_rate = _rate(injection_success)
    return {
        "benchmark": "agentdojo",
        "benchmark_version": benchmark_version,
        "suite": suite,
        "attack": attack,
        "pipeline": pipeline_name,
        "case_count": len(injection_success),
        "utility_rate": _rate(utility),
        "security_rate": round(1.0 - attack_success_rate, 4) if injection_success else 0.0,
        "attack_success_rate": attack_success_rate,
        "injection_task_utility_rate": _rate(injection_utility),
        "logdir": str(logdir) if logdir else None,
    }


def _validate_task_ids(
    suite: Any,
    user_tasks: tuple[str, ...],
    injection_tasks: tuple[str, ...],
) -> None:
    missing_users = sorted(set(user_tasks) - set(suite.user_tasks))
    missing_injections = sorted(set(injection_tasks) - set(suite.injection_tasks))
    if missing_users or missing_injections:
        details = []
        if missing_users:
            details.append(f"unknown user tasks: {', '.join(missing_users)}")
        if missing_injections:
            details.append(f"unknown injection tasks: {', '.join(missing_injections)}")
        raise ValueError("; ".join(details))


def _rate(values: list[bool]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _require_agentdojo() -> SimpleNamespace:
    dependencies = _load_agentdojo()
    if dependencies is None:
        raise AgentDojoUnavailableError(
            "AgentDojo is not installed. Install the zeroadr-agentdojo-bench package."
        )
    return dependencies


def _load_agentdojo() -> SimpleNamespace | None:
    try:
        import openai
        from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
        from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
        from agentdojo.agent_pipeline.llms.openai_llm import (
            OpenAILLM,
            _function_to_openai,
            _message_to_openai,
            _openai_to_assistant_message,
            chat_completion_request,
        )
        from agentdojo.agent_pipeline.pi_detector import PromptInjectionDetector as DojoPIDetector
        from agentdojo.attacks import load_attack
        from agentdojo.benchmark import benchmark_suite_with_injections
        from agentdojo.logging import OutputLogger
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.task_suite.load_suites import get_suite
        from agentdojo.types import get_text_content_as_str
    except ImportError:
        return None
    return SimpleNamespace(
        openai=openai,
        AgentPipeline=AgentPipeline,
        PipelineConfig=PipelineConfig,
        GroundTruthPipeline=GroundTruthPipeline,
        FunctionsRuntime=FunctionsRuntime,
        OpenAILLM=OpenAILLM,
        message_to_openai=_message_to_openai,
        function_to_openai=_function_to_openai,
        assistant_message_from_openai=_openai_to_assistant_message,
        chat_completion_request=chat_completion_request,
        PromptInjectionDetector=DojoPIDetector,
        load_attack=load_attack,
        benchmark_suite_with_injections=benchmark_suite_with_injections,
        OutputLogger=OutputLogger,
        get_suite=get_suite,
        get_text_content_as_str=get_text_content_as_str,
    )

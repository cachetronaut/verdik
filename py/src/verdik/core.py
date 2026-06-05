from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal, NotRequired, TypedDict

DefaultEffect = Literal["allow", "deny"]
ConditionOp = Literal[
    "exists",
    "eq",
    "neq",
    "in",
    "contains",
    "starts_with",
    "lte",
    "gte",
    "lt",
    "gt",
]


class Condition(TypedDict, total=False):
    all: list[Condition]
    any: list[Condition]
    not_: Condition
    field: str
    op: ConditionOp
    value: Any


class Obligation(TypedDict):
    kind: str
    detail: NotRequired[dict[str, Any]]


@dataclass(frozen=True)
class Rule:
    id: str
    effect: DefaultEffect
    when: Condition
    reason: str
    obligations: list[Obligation] = field(default_factory=list)


PolicyInput = dict[str, Any]


@dataclass(frozen=True)
class PolicyDecision:
    allow: bool
    reason: str
    obligations: list[Obligation] = field(default_factory=list)


@dataclass(frozen=True)
class MatchedRule:
    id: str
    effect: DefaultEffect
    reason: str


@dataclass(frozen=True)
class DecisionLog:
    matched: list[MatchedRule]
    obligations: list[Obligation]
    binding_rule_id: str | None = None
    defaulted: bool = False


@dataclass(frozen=True)
class EvaluationOptions:
    default_effect: DefaultEffect = "deny"
    default_reason: str | None = None


@dataclass(frozen=True)
class EvaluationResult:
    decision: PolicyDecision
    log: DecisionLog


class LocalPolicyEngine:
    def __init__(self, rules: list[Rule], options: EvaluationOptions | None = None) -> None:
        self._rules = rules
        self._options = options or EvaluationOptions()

    async def decide(self, value: PolicyInput) -> PolicyDecision:
        return evaluate(self._rules, value, self._options).decision


def evaluate(
    rules: list[Rule],
    value: PolicyInput,
    options: EvaluationOptions | None = None,
) -> EvaluationResult:
    options = options or EvaluationOptions()
    matched = [rule for rule in rules if matches_condition(rule.when, value)]
    denied = next((rule for rule in matched if rule.effect == "deny"), None)
    allow_rules = [rule for rule in matched if rule.effect == "allow"]
    obligations = _unique_obligations(
        obligation for rule in allow_rules for obligation in rule.obligations
    )

    if denied is not None:
        return EvaluationResult(
            PolicyDecision(False, denied.reason),
            _build_log(matched, denied.id, False, obligations),
        )

    first_allow = allow_rules[0] if allow_rules else None
    if first_allow is not None:
        return EvaluationResult(
            PolicyDecision(True, first_allow.reason, obligations),
            _build_log(matched, first_allow.id, False, obligations),
        )

    effect = options.default_effect
    return EvaluationResult(
        PolicyDecision(effect == "allow", options.default_reason or f"default_{effect}"),
        _build_log([], None, True, []),
    )


def matches_condition(condition: Condition, value: PolicyInput) -> bool:
    if "all" in condition:
        return all(matches_condition(child, value) for child in condition["all"])
    if "any" in condition:
        return any(matches_condition(child, value) for child in condition["any"])
    if "not_" in condition:
        return not matches_condition(condition["not_"], value)

    actual = read_path(value, condition["field"])
    expected = condition.get("value")
    op = condition["op"]
    if op == "exists":
        return actual is not None
    if op == "eq":
        return canonicalize(actual) == canonicalize(expected)
    if op == "neq":
        return canonicalize(actual) != canonicalize(expected)
    if op == "in":
        return isinstance(expected, list) and any(
            canonicalize(item) == canonicalize(actual) for item in expected
        )
    if op == "contains":
        if isinstance(actual, list):
            return any(canonicalize(item) == canonicalize(expected) for item in actual)
        return isinstance(actual, str) and isinstance(expected, str) and expected in actual
    if op == "starts_with":
        return isinstance(actual, str) and isinstance(expected, str) and actual.startswith(expected)
    if op == "lte":
        return _compare_number(actual, expected, lambda left, right: left <= right)
    if op == "gte":
        return _compare_number(actual, expected, lambda left, right: left >= right)
    if op == "lt":
        return _compare_number(actual, expected, lambda left, right: left < right)
    if op == "gt":
        return _compare_number(actual, expected, lambda left, right: left > right)


def read_path(value: PolicyInput, path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def canonicalize(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def create_local_policy_engine(
    rules: list[Rule], options: EvaluationOptions | None = None
) -> LocalPolicyEngine:
    return LocalPolicyEngine(rules, options)


def allow_all_rule(reason: str = "within_token") -> Rule:
    return Rule(
        id="allow_within_token",
        effect="allow",
        when={"field": "scope.action", "op": "exists"},
        reason=reason,
    )


def allow_within_token_policy() -> LocalPolicyEngine:
    return create_local_policy_engine([allow_all_rule()], EvaluationOptions(default_effect="deny"))


def layer_rules(*layers: list[Rule]) -> list[Rule]:
    return [rule for layer in layers for rule in layer]


def _build_log(
    rules: list[Rule],
    binding_rule_id: str | None,
    defaulted: bool,
    obligations: list[Obligation],
) -> DecisionLog:
    return DecisionLog(
        matched=[MatchedRule(rule.id, rule.effect, rule.reason) for rule in rules],
        binding_rule_id=binding_rule_id,
        defaulted=defaulted,
        obligations=obligations,
    )


def _unique_obligations(obligations: Any) -> list[Obligation]:
    seen: set[str] = set()
    out: list[Obligation] = []
    for obligation in obligations:
        key = canonicalize(obligation)
        if key in seen:
            continue
        seen.add(key)
        out.append(obligation)
    return out


def _compare_number(left: Any, right: Any, compare: Any) -> bool:
    return isinstance(left, int | float) and isinstance(right, int | float) and compare(left, right)

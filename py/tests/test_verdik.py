from __future__ import annotations

import asyncio

from verdik import (
    EvaluationOptions,
    Rule,
    allow_within_token_policy,
    canonicalize,
    create_local_policy_engine,
    evaluate,
    layer_rules,
    matches_condition,
)


def test_evaluate_allows_with_obligations() -> None:
    result = evaluate(
        [
            Rule(
                id="allow_echo",
                effect="allow",
                when={"field": "scope.resource", "op": "eq", "value": "tool.echo"},
                obligations=[{"kind": "emit_audit", "detail": {"level": "decision"}}],
                reason="echo_allowed",
            ),
            Rule(
                id="tag_dev",
                effect="allow",
                when={"field": "principal.claims.role", "op": "eq", "value": "developer"},
                obligations=[{"kind": "emit_audit", "detail": {"level": "decision"}}],
                reason="developer",
            ),
        ],
        _input(),
    )

    assert result.decision.allow
    assert result.decision.reason == "echo_allowed"
    assert result.decision.obligations == [{"kind": "emit_audit", "detail": {"level": "decision"}}]
    assert result.log.binding_rule_id == "allow_echo"


def test_deny_overrides_matching_allow() -> None:
    result = evaluate(
        [
            Rule(
                id="allow_all",
                effect="allow",
                when={"field": "scope.action", "op": "exists"},
                reason="allowed",
            ),
            Rule(
                id="deny_pii",
                effect="deny",
                when={"field": "claims.constraints.pii_export", "op": "eq", "value": True},
                reason="pii_requires_approval",
            ),
        ],
        _input(),
    )

    assert not result.decision.allow
    assert result.decision.reason == "pii_requires_approval"
    assert result.log.binding_rule_id == "deny_pii"


def test_default_effect_is_configurable() -> None:
    assert not evaluate([], _input()).decision.allow
    assert evaluate([], _input(), EvaluationOptions(default_effect="allow")).decision.allow


def test_nested_conditions_and_canonicalization() -> None:
    assert matches_condition(
        {
            "all": [
                {"field": "scope.resource", "op": "starts_with", "value": "tool."},
                {"field": "estimate.estimate.model_cost_usd", "op": "lte", "value": 1},
                {"not_": {"field": "principal.kind", "op": "eq", "value": "agent"}},
            ]
        },
        _input(),
    )
    assert canonicalize({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_local_policy_engine_and_layering() -> None:
    async def run() -> None:
        engine = create_local_policy_engine(
            layer_rules(
                [
                    Rule(
                        id="allow",
                        effect="allow",
                        when={"field": "scope.action", "op": "exists"},
                        reason="ok",
                    )
                ],
                [
                    Rule(
                        id="deny",
                        effect="deny",
                        when={"field": "scope.resource", "op": "eq", "value": "tool.payments"},
                        reason="payments_blocked",
                    )
                ],
            )
        )
        decision = await engine.decide(
            {
                "principal": {},
                "claims": {},
                "scope": {"action": "charge", "resource": "tool.payments"},
                "estimate": {},
            }
        )
        assert not decision.allow
        assert decision.reason == "payments_blocked"

        permissive = await allow_within_token_policy().decide(_input())
        assert permissive.allow
        assert permissive.reason == "within_token"

    asyncio.run(run())


def _input() -> dict[str, object]:
    return {
        "principal": {"id": "dev-user", "kind": "user", "claims": {"role": "developer"}},
        "claims": {"depth": 1, "constraints": {"pii_export": True}},
        "scope": {"action": "echo", "resource": "tool.echo"},
        "context": {"runId": "run_1"},
        "estimate": {"estimate": {"tool_calls": 1, "model_cost_usd": 0.01}},
    }

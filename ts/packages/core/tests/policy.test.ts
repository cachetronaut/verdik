import { describe, expect, it } from "vitest";
import type { PolicyInput, RuleSet } from "../src/index";
import { canonicalize, evaluate, matchesCondition } from "../src/index";

const input: PolicyInput = {
  principal: { id: "dev-user", kind: "user", claims: { role: "developer" } },
  claims: { depth: 1, constraints: { pii_export: true } },
  scope: { action: "echo", resource: "tool.echo" },
  context: { runId: "run_1" },
  estimate: { estimate: { tool_calls: 1, model_cost_usd: 0.01 } },
};

describe("evaluate", () => {
  it("allows with obligations from matching allow rules", () => {
    const rules: RuleSet = [
      {
        id: "allow_echo",
        effect: "allow",
        when: { field: "scope.resource", op: "eq", value: "tool.echo" },
        obligations: [{ kind: "emit_audit", detail: { level: "decision" } }],
        reason: "echo_allowed",
      },
      {
        id: "tag_dev",
        effect: "allow",
        when: { field: "principal.claims.role", op: "eq", value: "developer" },
        obligations: [{ kind: "emit_audit", detail: { level: "decision" } }],
        reason: "developer",
      },
    ];

    const decision = evaluate(rules, input);

    expect(decision.allow).toBe(true);
    expect(decision.reason).toBe("echo_allowed");
    expect(decision.obligations).toEqual([{ kind: "emit_audit", detail: { level: "decision" } }]);
    expect(decision.log).toMatchObject({
      bindingRuleId: "allow_echo",
      defaulted: false,
    });
  });

  it("lets deny rules override matching allow rules", () => {
    const decision = evaluate(
      [
        {
          id: "allow_all",
          effect: "allow",
          when: { field: "scope.action", op: "exists" },
          reason: "allowed",
        },
        {
          id: "deny_pii",
          effect: "deny",
          when: { field: "claims.constraints.pii_export", op: "eq", value: true },
          reason: "pii_requires_approval",
        },
      ],
      input,
    );

    expect(decision).toMatchObject({
      allow: false,
      reason: "pii_requires_approval",
      log: { bindingRuleId: "deny_pii" },
    });
  });

  it("defaults to deny unless configured otherwise", () => {
    expect(evaluate([], input)).toMatchObject({ allow: false, reason: "default_deny" });
    expect(evaluate([], input, { defaultEffect: "allow" })).toMatchObject({
      allow: true,
      reason: "default_allow",
    });
  });

  it("evaluates nested boolean conditions and numeric comparisons", () => {
    expect(
      matchesCondition(
        {
          all: [
            { field: "scope.resource", op: "starts_with", value: "tool." },
            { field: "estimate.estimate.model_cost_usd", op: "lte", value: 1 },
            { not: { field: "principal.kind", op: "eq", value: "agent" } },
          ],
        },
        input,
      ),
    ).toBe(true);
  });

  it("canonicalizes deterministically", () => {
    expect(canonicalize({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
  });
});

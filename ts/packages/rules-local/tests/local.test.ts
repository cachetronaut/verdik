import { describe, expect, it } from "vitest";
import { allowWithinTokenPolicy, createLocalPolicyEngine, layerRules } from "../src/index";

describe("LocalPolicyEngine", () => {
  it("decides through the core evaluator", async () => {
    const engine = createLocalPolicyEngine([
      {
        id: "deny_agent",
        effect: "deny",
        when: { field: "principal.kind", op: "eq", value: "agent" },
        reason: "agents_blocked",
      },
    ]);

    await expect(
      engine.decide({
        principal: { kind: "agent" },
        claims: {},
        scope: { action: "echo", resource: "tool.echo" },
        estimate: {},
      }),
    ).resolves.toMatchObject({ allow: false, reason: "agents_blocked" });
  });

  it("ships an explicit permissive MissionCtrl default", async () => {
    await expect(
      allowWithinTokenPolicy().decide({
        principal: { kind: "user" },
        claims: {},
        scope: { action: "echo", resource: "tool.echo" },
        estimate: {},
      }),
    ).resolves.toMatchObject({ allow: true, reason: "within_token" });
  });

  it("layers rule sets in order while preserving deny-overrides semantics", async () => {
    const engine = createLocalPolicyEngine(
      layerRules(
        [
          {
            id: "allow",
            effect: "allow",
            when: { field: "scope.action", op: "exists" },
            reason: "ok",
          },
        ],
        [
          {
            id: "deny",
            effect: "deny",
            when: { field: "scope.resource", op: "eq", value: "tool.payments" },
            reason: "payments_blocked",
          },
        ],
      ),
    );

    await expect(
      engine.decide({
        principal: {},
        claims: {},
        scope: { action: "charge", resource: "tool.payments" },
        estimate: {},
      }),
    ).resolves.toMatchObject({ allow: false, reason: "payments_blocked" });
  });
});

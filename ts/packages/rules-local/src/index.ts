import type {
  EvaluationOptions,
  PolicyDecision,
  PolicyEngine,
  PolicyInput,
  Rule,
  RuleSet,
} from "@verdik/core";
import { evaluate } from "@verdik/core";

export class LocalPolicyEngine implements PolicyEngine {
  constructor(
    private readonly rules: RuleSet,
    private readonly options: EvaluationOptions = {},
  ) {}

  async decide(input: PolicyInput): Promise<PolicyDecision> {
    return evaluate(this.rules, input, this.options);
  }
}

export function createLocalPolicyEngine(
  rules: RuleSet,
  options: EvaluationOptions = {},
): LocalPolicyEngine {
  return new LocalPolicyEngine(rules, options);
}

export function allowAllRule(reason = "within_token"): Rule {
  return {
    id: "allow_within_token",
    effect: "allow",
    when: { field: "scope.action", op: "exists" },
    reason,
  };
}

export function allowWithinTokenPolicy(): LocalPolicyEngine {
  return createLocalPolicyEngine([allowAllRule()], { defaultEffect: "deny" });
}

export function layerRules(...layers: readonly RuleSet[]): RuleSet {
  return layers.flat();
}

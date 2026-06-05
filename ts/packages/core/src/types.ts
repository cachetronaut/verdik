export type DefaultEffect = "allow" | "deny";
export type ConditionOp =
  | "exists"
  | "eq"
  | "neq"
  | "in"
  | "contains"
  | "starts_with"
  | "lte"
  | "gte"
  | "lt"
  | "gt";

export type Condition =
  | {
      readonly all: readonly Condition[];
    }
  | {
      readonly any: readonly Condition[];
    }
  | {
      readonly not: Condition;
    }
  | {
      readonly field: string;
      readonly op: ConditionOp;
      readonly value?: unknown;
    };

export interface Obligation {
  readonly kind: string;
  readonly detail?: Readonly<Record<string, unknown>>;
}

export interface Rule {
  readonly id: string;
  readonly effect: DefaultEffect;
  readonly when: Condition;
  readonly obligations?: readonly Obligation[];
  readonly reason: string;
}

export type RuleSet = readonly Rule[];

export interface PolicyInput {
  readonly principal: Readonly<Record<string, unknown>>;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly scope: Readonly<Record<string, unknown>>;
  readonly context?: Readonly<Record<string, unknown>>;
  readonly estimate: Readonly<Record<string, unknown>>;
  readonly [key: string]: unknown;
}

export interface PolicyDecision {
  readonly allow: boolean;
  readonly reason: string;
  readonly obligations?: readonly Obligation[];
}

export interface MatchedRule {
  readonly id: string;
  readonly effect: DefaultEffect;
  readonly reason: string;
}

export interface DecisionLog {
  readonly matched: readonly MatchedRule[];
  readonly bindingRuleId?: string;
  readonly defaulted: boolean;
  readonly obligations: readonly Obligation[];
}

export interface EvaluationOptions {
  readonly defaultEffect?: DefaultEffect;
  readonly defaultReason?: string;
}

export interface PolicyEngine {
  decide(input: PolicyInput): Promise<PolicyDecision>;
}

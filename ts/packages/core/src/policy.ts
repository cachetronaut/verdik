import { canonicalize } from "./canonical.js";
import type {
  Condition,
  DecisionLog,
  EvaluationOptions,
  MatchedRule,
  Obligation,
  PolicyDecision,
  PolicyInput,
  RuleSet,
} from "./types.js";

export function evaluate(
  rules: RuleSet,
  input: PolicyInput,
  options: EvaluationOptions = {},
): PolicyDecision & { readonly log: DecisionLog } {
  const matched = rules.filter((rule) => matchesCondition(rule.when, input));
  const denied = matched.find((rule) => rule.effect === "deny");
  const allowRules = matched.filter((rule) => rule.effect === "allow");
  const obligations = uniqueObligations(allowRules.flatMap((rule) => rule.obligations ?? []));

  if (denied !== undefined) {
    return {
      allow: false,
      reason: denied.reason,
      log: buildLog(matched, denied.id, false, obligations),
    };
  }
  const firstAllow = allowRules[0];
  if (firstAllow !== undefined) {
    return {
      allow: true,
      reason: firstAllow.reason,
      obligations: obligations.length > 0 ? obligations : undefined,
      log: buildLog(matched, firstAllow.id, false, obligations),
    };
  }

  const effect = options.defaultEffect ?? "deny";
  return {
    allow: effect === "allow",
    reason: options.defaultReason ?? `default_${effect}`,
    log: buildLog([], undefined, true, []),
  };
}

export function matchesCondition(condition: Condition, input: PolicyInput): boolean {
  if ("all" in condition) {
    return condition.all.every((child) => matchesCondition(child, input));
  }
  if ("any" in condition) {
    return condition.any.some((child) => matchesCondition(child, input));
  }
  if ("not" in condition) {
    return !matchesCondition(condition.not, input);
  }

  const actual = readPath(input, condition.field);
  switch (condition.op) {
    case "exists":
      return actual !== undefined;
    case "eq":
      return canonicalize(actual) === canonicalize(condition.value);
    case "neq":
      return canonicalize(actual) !== canonicalize(condition.value);
    case "in":
      return Array.isArray(condition.value)
        ? condition.value.some((value) => canonicalize(value) === canonicalize(actual))
        : false;
    case "contains":
      return Array.isArray(actual)
        ? actual.some((value) => canonicalize(value) === canonicalize(condition.value))
        : typeof actual === "string" && typeof condition.value === "string"
          ? actual.includes(condition.value)
          : false;
    case "starts_with":
      return typeof actual === "string" && typeof condition.value === "string"
        ? actual.startsWith(condition.value)
        : false;
    case "lte":
      return compareNumber(actual, condition.value, (left, right) => left <= right);
    case "gte":
      return compareNumber(actual, condition.value, (left, right) => left >= right);
    case "lt":
      return compareNumber(actual, condition.value, (left, right) => left < right);
    case "gt":
      return compareNumber(actual, condition.value, (left, right) => left > right);
  }
}

export function readPath(input: PolicyInput, path: string): unknown {
  return path.split(".").reduce<unknown>((current, part) => {
    if (current === null || typeof current !== "object") {
      return undefined;
    }
    return (current as Record<string, unknown>)[part];
  }, input);
}

function buildLog(
  rules: RuleSet,
  bindingRuleId: string | undefined,
  defaulted: boolean,
  obligations: readonly Obligation[],
): DecisionLog {
  const matched: MatchedRule[] = rules.map((rule) => ({
    id: rule.id,
    effect: rule.effect,
    reason: rule.reason,
  }));
  return {
    matched,
    bindingRuleId,
    defaulted,
    obligations,
  };
}

function compareNumber(
  left: unknown,
  right: unknown,
  compare: (left: number, right: number) => boolean,
): boolean {
  return typeof left === "number" && typeof right === "number" ? compare(left, right) : false;
}

function uniqueObligations(obligations: readonly Obligation[]): readonly Obligation[] {
  const seen = new Set<string>();
  const out: Obligation[] = [];
  for (const obligation of obligations) {
    const key = canonicalize(obligation);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(obligation);
  }
  return out;
}

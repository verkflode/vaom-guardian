// The composite confidence score (VAOM v5 Section 8), computed from a human-approved scoring policy exactly
// as written. Deterministic: the same policy, facts and history give the same score.
//
// Containment rules it holds to:
// - Every input it can't read counts against the score: a missing fact fails its check or rule, an
//   unreadable history fires its signal.
// - The agent's stated certainty never adds: it can only lower the composite or cap the level.
// - Gates and floors only cap. Nothing here can lift a placement past what its composite earns.
import { evalCondition } from "../eval/conditions.ts";
import { factOf } from "../eval/facts.ts";
import type { FactValue, Money, Reason } from "../eval/types.ts";
import { durationSeconds } from "../lint/duration.ts";
import { DIMENSIONS } from "../lint/scoring.ts";

type Validated = any;

export type Level = "high" | "medium" | "low";
export type Dimension = (typeof DIMENSIONS)[number];

export interface DimensionScore {
  score: number;
  /** Checks or rules that didn't hold. */
  failed?: string[];
  /** Anomaly signals that fired. */
  fired?: string[];
}

export interface ScoreResult {
  policy: { id: string; version: string };
  /** The composite, after any stated-certainty cap. */
  value: number;
  /** The strictest level the policy's gates, floors, hard rules and stated certainty allow. */
  cap?: "medium" | "low";
  dimensions: Partial<Record<Dimension, DimensionScore>>;
  reasons: Reason[];
}

/**
 * The Guardian's own decision history, as anomaly signals read it. Values are passed raw; the
 * implementation compares them in the form records hold them (in clear or as a keyed digest).
 * `windowMs` null means all loaded history. Every method returns null when history can't be read.
 */
export interface History {
  /** Did an executed decision on `row` carry this value of `fact`? */
  seen(row: string, fact: string, value: FactValue, windowMs: number | null): boolean | null;
  /** Values of `fact` from executed decisions on `row` whose `group` facts match. */
  values(row: string, fact: string, group: Record<string, FactValue>, windowMs: number | null): FactValue[] | null;
  /** Decisions on `row` whose `group` facts match, whatever their outcome. */
  count(row: string, group: Record<string, FactValue>, windowMs: number): number | null;
}

export interface ScoreInput {
  row: string;
  facts: Readonly<Record<string, FactValue>>;
  history?: History;
  /** The agent's stated certainty for this call, if the host passed one. */
  statedCertainty?: number;
}

const STRICTER: Record<"medium" | "low", number> = { medium: 1, low: 2 };

export function score(policy: Validated, input: ScoreInput): ScoreResult {
  const reasons: Reason[] = [];
  const dimensions: Partial<Record<Dimension, DimensionScore>> = {};
  let cap: "medium" | "low" | undefined;
  const capAt = (level: "medium" | "low", code: string, detail: string) => {
    if (!cap || STRICTER[level] > STRICTER[cap]) cap = level;
    reasons.push({ code, detail, row: input.row });
  };
  const holds = (c: Validated) => evalCondition(c, (f) => factOf(input.facts, f), "fact") === true;

  const d = policy.dimensions;
  if (d.dataCompleteness) {
    const failed = (d.dataCompleteness.checks as Validated[])
      .filter((c) => !((c.present ?? []) as string[]).every((f) => Object.hasOwn(input.facts, f)) || (c.when !== undefined && !holds(c.when)))
      .map((c) => c.id as string);
    dimensions.dataCompleteness = withList({ score: 1 - failed.length / d.dataCompleteness.checks.length }, "failed", failed);
  }
  if (d.ruleMatch) {
    const rules = d.ruleMatch.rules as Validated[];
    const w = (r: Validated) => (r.weight ?? 1) as number;
    const failedRules = rules.filter((r) => !holds(r.when));
    const total = rules.reduce((a, r) => a + w(r), 0);
    dimensions.ruleMatch = withList({ score: clamp(1 - failedRules.reduce((a, r) => a + w(r), 0) / total) }, "failed", failedRules.map((r) => r.id));
    for (const r of failedRules) if (r.hard) capAt("medium", "confidence.hard-rule", `rule ${r.id} failed`);
  }
  if (d.anomaly) {
    const fired: string[] = [];
    let penalty = 0;
    for (const g of d.anomaly.signals as Validated[]) {
      const f = fires(g, input);
      if (f === null) reasons.push({ code: "anomaly.history-unreadable", detail: g.id, row: input.row });
      if (f !== false) { fired.push(g.id); penalty += g.penalty; }
    }
    dimensions.anomaly = withList({ score: clamp(1 - penalty) }, "fired", fired);
  }

  let value = 0;
  for (const k of DIMENSIONS) {
    const dim = d[k], got = dimensions[k];
    if (!dim || !got) continue;
    value += dim.weight * got.score;
    if (dim.floor === "must-pass") { if (got.score < 1) capAt("low", "confidence.gate", `${k} must pass`); }
    else if (got.score < dim.floor) capAt("medium", "confidence.floor", `${k} below its floor`);
  }
  value = clamp(value);

  const mc = policy.modelCertainty;
  if (mc) {
    const stated = input.statedCertainty;
    if (stated === undefined || !Number.isFinite(stated) || stated < 0 || stated > 1) {
      if (stated !== undefined) reasons.push({ code: "confidence.certainty-invalid", row: input.row });
      if (mc.required) capAt("low", "confidence.certainty-missing", "the policy requires a stated certainty");
    } else {
      value = Math.min(value, stated);
      if (mc.floor !== undefined && stated < mc.floor) capAt("medium", "confidence.certainty-floor", "stated certainty below its floor");
    }
  }

  return { policy: { id: policy.id, version: policy.version }, value, ...(cap ? { cap } : {}), dimensions, reasons };
}

/** Apply a policy's cap to the level a row's thresholds gave. */
export function capLevel(level: Level, cap: "medium" | "low" | undefined): Level {
  if (cap === "low") return "low";
  if (cap === "medium" && level === "high") return "medium";
  return level;
}

/** true or false, or null when history couldn't be read (which the caller treats as firing). */
function fires(g: Validated, input: ScoreInput): boolean | null {
  const h = input.history;
  if (!h) return null;
  // A window that can't be read, or is zero, would count nothing: the signal fires (lint refuses both).
  const windowS = g.window ? durationSeconds(g.window) : null;
  if (g.window && !windowS) return null;
  const windowMs = windowS === null ? null : windowS * 1000;
  const group: Record<string, FactValue> = {};
  for (const f of (g.groupBy ?? []) as string[]) {
    const v = factOf(input.facts, f);
    if (v === undefined) return true; // no group to compare against: unfamiliar by definition
    group[f] = v;
  }
  switch (g.kind) {
    case "unseen": {
      const v = factOf(input.facts, g.fact);
      if (v === undefined) return true;
      const seen = h.seen(input.row, g.fact, v, windowMs);
      return seen === null ? null : !seen;
    }
    case "unusual-value": {
      const v = numeric(factOf(input.facts, g.fact));
      if (v === null) return true;
      const prior = h.values(input.row, g.fact, group, windowMs);
      if (prior === null) return null;
      const xs = prior.map(numeric).filter((x): x is { n: number; currency?: string } => x !== null && x.currency === v.currency).map((x) => x.n);
      if (xs.length === 0 || xs.length < g.minHistory) return true;
      return v.n > g.factor * median(xs);
    }
    case "burst": {
      if (windowMs === null) return null;
      const n = h.count(input.row, group, windowMs);
      return n === null ? null : n >= g.count;
    }
    default:
      return true;
  }
}

function numeric(v: FactValue | undefined): { n: number; currency?: string } | null {
  if (typeof v === "number" && Number.isFinite(v)) return { n: v };
  if (v && typeof v === "object" && typeof (v as Money).amount === "string") return { n: Number((v as Money).amount), currency: (v as Money).currency };
  return null;
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b), m = s.length >> 1;
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

function clamp(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

function withList(s: DimensionScore, key: "failed" | "fired", list: string[]): DimensionScore {
  return list.length ? { ...s, [key]: list } : s;
}

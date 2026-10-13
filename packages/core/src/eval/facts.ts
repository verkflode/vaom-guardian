// Fact extraction: read each fact from the call's (unwrapped) arguments or a binding constant, and
// check it against its declared type. A value of the wrong type is treated as missing.
import { isDecimal } from "./decimal.ts";
import { resolvePointer } from "./pointer.ts";
import type { FactValue, Money } from "./types.ts";

type Validated = any;

/** A fact's value, read as an own property only: a fact named like an Object.prototype member is missing
 *  unless it was extracted. */
export function factOf<T>(facts: Readonly<Record<string, T>>, name: string): T | undefined {
  return Object.hasOwn(facts, name) ? facts[name] : undefined;
}

export type Extracted = { ok: true; value: FactValue } | { ok: false; why: string };

export function extractFact(def: Validated, ex: Validated, args: unknown): Extracted {
  if (def.type === "money") {
    if (!ex || typeof ex !== "object" || !("amount" in ex)) return { ok: false, why: "binding uses a plain extractor for a money fact" };
    const amount = readRaw(ex.amount, args), currency = readRaw(ex.currency, args);
    const a = toDecimal(amount);
    if (a === null) return { ok: false, why: `amount ${describe(amount)} is not an exact decimal` };
    if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) return { ok: false, why: `currency ${describe(currency)} is not an ISO 4217 code` };
    const m: Money = { amount: a, currency };
    return { ok: true, value: m };
  }
  const raw = readRaw(ex, args);
  if (raw === undefined) return { ok: false, why: "not present" };
  switch (def.type) {
    case "string":
      return typeof raw === "string" ? { ok: true, value: raw } : { ok: false, why: `expected a string, got ${describe(raw)}` };
    case "integer":
      return typeof raw === "number" && Number.isSafeInteger(raw) ? { ok: true, value: raw } : { ok: false, why: `expected an integer, got ${describe(raw)}` };
    case "number":
      return typeof raw === "number" && Number.isFinite(raw) ? { ok: true, value: raw } : { ok: false, why: `expected a number, got ${describe(raw)}` };
    case "boolean":
      return typeof raw === "boolean" ? { ok: true, value: raw } : { ok: false, why: `expected a boolean, got ${describe(raw)}` };
    case "timestamp":
      return typeof raw === "string" && !Number.isNaN(Date.parse(raw)) && /\d{4}-\d{2}-\d{2}T/.test(raw)
        ? { ok: true, value: raw }
        : { ok: false, why: `expected an ISO 8601 timestamp, got ${describe(raw)}` };
    default:
      return { ok: false, why: `unknown fact type ${def.type}` };
  }
}

function readRaw(ex: Validated, args: unknown): unknown {
  if (!ex || typeof ex !== "object") return undefined;
  if ("const" in ex) return ex.const;
  if (typeof ex.arg === "string") return resolvePointer(args, ex.arg);
  return undefined;
}

/** Decimal strings as they are; JSON numbers only when they are whole, so no float rounding sneaks in. */
function toDecimal(v: unknown): string | null {
  if (isDecimal(v)) return v;
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return String(v);
  return null;
}

/** Describe a value by its type only. Reasons end up in decision records, and a fact recorded as a
 *  digest (a counterparty, a person) must not reappear there in clear through an error message. */
function describe(v: unknown): string {
  if (v === undefined) return "(missing)";
  if (v === null) return "null";
  if (Array.isArray(v)) return "an array";
  if (typeof v === "string") return `a string of ${v.length} characters`;
  if (typeof v === "number") return Number.isInteger(v) ? "a whole number" : "a fractional number";
  return `a ${typeof v}`;
}

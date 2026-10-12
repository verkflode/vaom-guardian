// Types for the generated standalone validators (see scripts/gen-validators.mjs).
export interface SchemaError {
  instancePath: string;
  schemaPath: string;
  keyword: string;
  params: Record<string, unknown>;
  message?: string;
}
export interface Validator {
  (data: unknown): boolean;
  errors?: SchemaError[] | null;
}
export const validateMatrix01: Validator;
export const validateMatrix02: Validator;
export const validateBinding01: Validator;
export const validateScoring01: Validator;
export const validateSeeds01: Validator;
export const validateProbes01: Validator;
export const validateProbeResult01: Validator;
export const validateDecision03: Validator;
export const validateDecision04: Validator;

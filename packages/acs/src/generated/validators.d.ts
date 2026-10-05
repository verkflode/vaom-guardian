// Types for the generated standalone validators (see scripts/gen-validators.mjs).
export interface SchemaError { instancePath: string; schemaPath: string; keyword: string; params: Record<string, unknown>; message?: string }
export interface Validator { (data: unknown): boolean; errors?: SchemaError[] | null }
export const validateRequestEnvelope: Validator;
export const validateResponseEnvelope: Validator;
export const validateClientHello: Validator;
export const validateServerHello: Validator;
export const validateToolCallRequest: Validator;
export const validateToolCallResult: Validator;
export const validateSessionStart: Validator;
export const validateSubagentStart: Validator;

// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: the JSON Schema subset evaluator behind the three credential schemas.
import { describe, expect, it } from 'vitest';
import {
  JsonSchemaError,
  assertSupportedSchema,
  parseDateTime,
  validateJsonSchema,
  type JsonSchema,
} from '../../../../src/core/credentials/json-schema.js';

const messages = (schema: JsonSchema, value: unknown): string[] =>
  validateJsonSchema(schema, value).map((violation) => `${violation.path}: ${violation.message}`);

describe('parseDateTime', () => {
  it('reads RFC 3339 date-times with an offset and nothing else', () => {
    expect(parseDateTime('2026-01-01T00:00:00Z')).toBe(Date.UTC(2026, 0, 1));
    expect(parseDateTime('2026-01-01T02:00:00.250+02:00')).toBe(Date.UTC(2026, 0, 1, 0, 0, 0, 250));
    expect(parseDateTime('2026-01-01t00:00:00z')).toBe(Date.UTC(2026, 0, 1));
    expect(parseDateTime('2026-01-01T00:00:00')).toBeUndefined();
    expect(parseDateTime('2026-13-01T00:00:00Z')).toBeUndefined();
    expect(parseDateTime(1)).toBeUndefined();
    expect(parseDateTime(undefined)).toBeUndefined();
  });
});

describe('validateJsonSchema', () => {
  it('checks types, including integer versus number and null', () => {
    expect(messages({ type: 'integer' }, 1)).toEqual([]);
    expect(messages({ type: 'integer' }, 1.5)).toEqual(['$: expected type integer, got number']);
    expect(messages({ type: 'number' }, 1)).toEqual([]);
    expect(messages({ type: ['string', 'null'] }, null)).toEqual([]);
    expect(messages({ type: 'array' }, {})).toEqual(['$: expected type array, got object']);
    expect(messages({ type: 'object' }, [])).toEqual(['$: expected type object, got array']);
    expect(messages({ type: 'boolean' }, 'x')).toEqual(['$: expected type boolean, got string']);
  });

  it('checks const, enum, minLength, pattern and date-time format on strings', () => {
    expect(messages({ const: 'a' }, 'b')).toEqual(['$: expected the constant "a"']);
    expect(messages({ const: { k: [1, { z: 1, a: 2 }] } }, { k: [1, { a: 2, z: 1 }] })).toEqual([]);
    expect(messages({ enum: ['a', 'b'] }, 'c')).toEqual(['$: expected one of ["a","b"]']);
    expect(messages({ minLength: 2 }, 'a')).toEqual(['$: expected at least 2 characters']);
    expect(messages({ pattern: '^did:' }, 'nope')).toEqual(['$: does not match pattern ^did:']);
    expect(messages({ format: 'date-time' }, '2026-01-01T00:00:00')).toEqual(['$: is not an RFC 3339 date-time with offset']);
    expect(messages({ format: 'date-time' }, '2026-01-01T00:00:00Z')).toEqual([]);
    expect(messages({ format: 'date-time', minLength: 1, pattern: 'x' }, 7)).toEqual([]);
  });

  it('checks arrays: minItems, items and contains', () => {
    const schema: JsonSchema = { type: 'array', minItems: 2, items: { type: 'string' }, contains: { const: 'b' } };
    expect(messages(schema, ['a', 'b'])).toEqual([]);
    expect(messages(schema, ['a'])).toEqual(['$: expected at least 2 items', '$: no item satisfies {"const":"b"}']);
    expect(messages(schema, ['b', 1])).toEqual(['$[1]: expected type string, got integer']);
  });

  it('checks objects: required, properties, additionalProperties as false and as a schema', () => {
    const closed: JsonSchema = { type: 'object', required: ['a'], properties: { a: { type: 'string' } }, additionalProperties: false };
    expect(messages(closed, { a: 'x' })).toEqual([]);
    expect(messages(closed, { b: 1 })).toEqual(['$: missing required member "a"', '$.b: unknown member is not allowed']);
    const open: JsonSchema = { type: 'object', properties: { a: { type: 'string' } }, additionalProperties: { type: 'number' } };
    expect(messages(open, { a: 'x', b: 1 })).toEqual([]);
    expect(messages(open, { b: 'y' })).toEqual(['$.b: expected type number, got string']);
    const unconstrained: JsonSchema = { type: 'object', properties: { a: { type: 'string' } }, additionalProperties: true };
    expect(messages(unconstrained, { b: 'y' })).toEqual([]);
  });

  it('checks allOf, anyOf and oneOf', () => {
    expect(messages({ allOf: [{ type: 'string' }, { minLength: 2 }] }, 'a')).toEqual(['$: expected at least 2 characters']);
    expect(messages({ anyOf: [{ type: 'string' }, { type: 'number' }] }, true)).toEqual(['$: matches none of the anyOf alternatives']);
    expect(messages({ anyOf: [{ type: 'string' }, { type: 'number' }] }, 1)).toEqual([]);
    expect(messages({ oneOf: [{ type: 'string' }, { minLength: 1 }] }, 'a')).toEqual(['$: matches 2 oneOf alternatives, expected exactly one']);
    expect(messages({ oneOf: [{ type: 'string' }, { type: 'number' }] }, 1)).toEqual([]);
  });

  it('resolves local $ref into $defs and refuses anything else', () => {
    const schema: JsonSchema = { $defs: { Did: { type: 'string', pattern: '^did:' } }, properties: { id: { $ref: '#/$defs/Did' } } };
    expect(messages(schema, { id: 'did:x' })).toEqual([]);
    expect(messages(schema, { id: 'x' })).toEqual(['$.id: does not match pattern ^did:']);
    expect(() => validateJsonSchema({ properties: { id: { $ref: 'https://elsewhere' } } }, { id: 1 })).toThrow(JsonSchemaError);
    expect(() => validateJsonSchema({ properties: { id: { $ref: '#/$defs/Missing' } } }, { id: 1 })).toThrow(/does not resolve/);
    expect(() => validateJsonSchema({ $defs: { Did: 'x' }, properties: { id: { $ref: '#/$defs/Did/x' } } }, { id: 1 })).toThrow(/does not resolve/);
  });

  it('refuses a schema that uses a keyword it does not evaluate, wherever it appears', () => {
    expect(() => assertSupportedSchema({ maximum: 1 })).toThrow('Unsupported JSON Schema keyword "maximum" at #');
    expect(() => assertSupportedSchema({ properties: { a: { maximum: 1 } } })).toThrow('at #/properties/a');
    expect(() => assertSupportedSchema({ $defs: { A: { uniqueItems: true } } })).toThrow('at #/$defs/A');
    expect(() => assertSupportedSchema({ items: { not: {} } })).toThrow('at #/items');
    expect(() => assertSupportedSchema({ allOf: [{}, { if: {} }] })).toThrow('at #/allOf/1');
    expect(() => assertSupportedSchema({ additionalProperties: { dependentRequired: {} } })).toThrow('at #/additionalProperties');
    // Non-schema values in those positions are ignored, as they are by the evaluator.
    expect(() => assertSupportedSchema({ properties: null, items: true, allOf: 'x', $defs: 1 })).not.toThrow();
  });
});

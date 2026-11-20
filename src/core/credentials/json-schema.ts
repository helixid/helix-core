// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * The JSON Schema (draft 2020-12) subset the three KYA-OS story F-1 credential
 * schemas use, evaluated without a dependency: `type`, `properties`,
 * `required`, `additionalProperties`, `items`, `minItems`, `contains`,
 * `enum`, `const`, `pattern`, `minLength`, `format: date-time`, `allOf`,
 * `anyOf`, `oneOf` and `$ref` into `#/$defs`. Every keyword outside this
 * list is refused at load time, so a schema never silently validates less
 * than it says. Mirrored in helix-sdk-py's `credentials.py`.
 */

export interface JsonSchema {
  [keyword: string]: unknown;
}

export interface SchemaViolation {
  /** JSON pointer-like path of the offending value (`$`, `$.credentialSubject.id`). */
  path: string;
  message: string;
}

const KNOWN_KEYWORDS = new Set([
  '$schema',
  '$id',
  '$defs',
  'title',
  'description',
  'examples',
  'type',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'minItems',
  'contains',
  'enum',
  'const',
  'pattern',
  'minLength',
  'format',
  'allOf',
  'anyOf',
  'oneOf',
  '$ref',
]);

/** RFC 3339 date-time with its offset from UTC (`Z` or `+hh:mm`); the form KYA-OS SPEC §6.6 requires. */
export const DATE_TIME_PATTERN =
  /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

/** Milliseconds since the epoch of an RFC 3339 date-time with offset, or undefined for any other value. */
export function parseDateTime(value: unknown): number | undefined {
  if (typeof value !== 'string' || !DATE_TIME_PATTERN.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : ms;
}

function jsonType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function typeMatches(expected: string, value: unknown): boolean {
  const actual = jsonType(value);
  if (expected === 'number') return actual === 'number' || actual === 'integer';
  return actual === expected;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, sortKeys(record[key])]),
    );
  }
  return value;
}

export class JsonSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JsonSchemaError';
  }
}

/** Refuses a schema that uses a keyword this evaluator does not implement. */
export function assertSupportedSchema(schema: JsonSchema, path = '#'): void {
  for (const keyword of Object.keys(schema)) {
    if (!KNOWN_KEYWORDS.has(keyword)) {
      throw new JsonSchemaError(`Unsupported JSON Schema keyword "${keyword}" at ${path}`);
    }
  }
  const nested = (value: unknown, where: string): void => {
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      assertSupportedSchema(value as JsonSchema, where);
    }
  };
  for (const key of ['$defs', 'properties'] as const) {
    const members = schema[key];
    if (members !== null && typeof members === 'object') {
      for (const [name, sub] of Object.entries(members as Record<string, unknown>)) nested(sub, `${path}/${key}/${name}`);
    }
  }
  for (const key of ['items', 'contains', 'additionalProperties'] as const) nested(schema[key], `${path}/${key}`);
  for (const key of ['allOf', 'anyOf', 'oneOf'] as const) {
    const list = schema[key];
    if (Array.isArray(list)) list.forEach((sub, index) => nested(sub, `${path}/${key}/${index}`));
  }
}

function resolveRef(root: JsonSchema, ref: unknown): JsonSchema {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) {
    throw new JsonSchemaError(`Only local $ref values are supported, got ${String(ref)}`);
  }
  let current: unknown = root;
  for (const segment of ref.slice(2).split('/')) {
    if (current === null || typeof current !== 'object') {
      throw new JsonSchemaError(`$ref ${ref} does not resolve`);
    }
    current = (current as Record<string, unknown>)[segment];
  }
  if (current === null || typeof current !== 'object') {
    throw new JsonSchemaError(`$ref ${ref} does not resolve`);
  }
  return current as JsonSchema;
}

function validateAt(
  root: JsonSchema,
  schema: JsonSchema,
  value: unknown,
  path: string,
  out: SchemaViolation[],
): void {
  if (schema['$ref'] !== undefined) {
    validateAt(root, resolveRef(root, schema['$ref']), value, path, out);
  }

  const type = schema['type'];
  if (type !== undefined) {
    const allowed = Array.isArray(type) ? (type as string[]) : [type as string];
    if (!allowed.some((candidate) => typeMatches(candidate, value))) {
      out.push({ path, message: `expected type ${allowed.join(' | ')}, got ${jsonType(value)}` });
      return;
    }
  }

  if (schema['const'] !== undefined && !deepEqual(schema['const'], value)) {
    out.push({ path, message: `expected the constant ${JSON.stringify(schema['const'])}` });
  }
  const allowedValues = schema['enum'];
  if (Array.isArray(allowedValues) && !allowedValues.some((candidate) => deepEqual(candidate, value))) {
    out.push({ path, message: `expected one of ${JSON.stringify(allowedValues)}` });
  }

  if (typeof value === 'string') {
    const minLength = schema['minLength'];
    if (typeof minLength === 'number' && value.length < minLength) {
      out.push({ path, message: `expected at least ${minLength} characters` });
    }
    const pattern = schema['pattern'];
    if (typeof pattern === 'string' && !new RegExp(pattern).test(value)) {
      out.push({ path, message: `does not match pattern ${pattern}` });
    }
    if (schema['format'] === 'date-time' && parseDateTime(value) === undefined) {
      out.push({ path, message: 'is not an RFC 3339 date-time with offset' });
    }
  }

  if (Array.isArray(value)) {
    const minItems = schema['minItems'];
    if (typeof minItems === 'number' && value.length < minItems) {
      out.push({ path, message: `expected at least ${minItems} items` });
    }
    const items = schema['items'];
    if (items !== null && typeof items === 'object') {
      value.forEach((item, index) => validateAt(root, items as JsonSchema, item, `${path}[${index}]`, out));
    }
    const contains = schema['contains'];
    if (contains !== null && typeof contains === 'object') {
      const found = value.some((item) => countViolations(root, contains as JsonSchema, item) === 0);
      if (!found) out.push({ path, message: `no item satisfies ${JSON.stringify(contains)}` });
    }
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    const required = schema['required'];
    if (Array.isArray(required)) {
      for (const name of required as string[]) {
        if (!(name in record)) out.push({ path, message: `missing required member "${name}"` });
      }
    }
    const properties = (schema['properties'] ?? {}) as Record<string, JsonSchema>;
    for (const [name, sub] of Object.entries(properties)) {
      if (name in record) validateAt(root, sub, record[name], `${path}.${name}`, out);
    }
    const additional = schema['additionalProperties'];
    if (additional !== undefined && additional !== true) {
      for (const name of Object.keys(record)) {
        if (name in properties) continue;
        if (additional === false) {
          out.push({ path: `${path}.${name}`, message: 'unknown member is not allowed' });
        } else {
          validateAt(root, additional as JsonSchema, record[name], `${path}.${name}`, out);
        }
      }
    }
  }

  const allOf = schema['allOf'];
  if (Array.isArray(allOf)) {
    for (const sub of allOf as JsonSchema[]) validateAt(root, sub, value, path, out);
  }
  const anyOf = schema['anyOf'];
  if (Array.isArray(anyOf)) {
    const passing = (anyOf as JsonSchema[]).filter((sub) => countViolations(root, sub, value) === 0).length;
    if (passing === 0) out.push({ path, message: 'matches none of the anyOf alternatives' });
  }
  const oneOf = schema['oneOf'];
  if (Array.isArray(oneOf)) {
    const passing = (oneOf as JsonSchema[]).filter((sub) => countViolations(root, sub, value) === 0).length;
    if (passing !== 1) out.push({ path, message: `matches ${passing} oneOf alternatives, expected exactly one` });
  }
}

function countViolations(root: JsonSchema, schema: JsonSchema, value: unknown): number {
  const out: SchemaViolation[] = [];
  validateAt(root, schema, value, '$', out);
  return out.length;
}

/** Every way `value` breaks `schema`; empty when it conforms. */
export function validateJsonSchema(schema: JsonSchema, value: unknown): SchemaViolation[] {
  assertSupportedSchema(schema);
  const out: SchemaViolation[] = [];
  validateAt(schema, schema, value, '$', out);
  return out;
}

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
 * The subset of JSON Schema 2020-12 the KYA-OS Entity Card schema uses,
 * evaluated strictly: `type`, `enum`, `const`, `required`, `properties`,
 * `additionalProperties`, `pattern`, `minLength`, `minItems`, `minimum`,
 * `items`, `oneOf`, `format` (`date-time`, `uri`) and `$ref` into `$defs`.
 * A keyword outside this subset is a programming error, not a silent pass.
 */

export interface SchemaIssue {
  /** JSON-pointer-like path of the offending value, '' for the root. */
  path: string;
  message: string;
}

export type JsonSchema = Record<string, unknown>;

const KNOWN_KEYWORDS = new Set([
  '$schema', '$id', 'title', 'description', 'examples', '$defs', '$ref',
  'type', 'enum', 'const', 'required', 'properties', 'additionalProperties',
  'pattern', 'minLength', 'minItems', 'minimum', 'items', 'oneOf', 'format',
]);

const RFC3339_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

function jsonType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function typeMatches(value: unknown, type: string): boolean {
  const actual = jsonType(value);
  if (type === 'number') return actual === 'number' || actual === 'integer';
  return actual === type;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function resolveRef(ref: unknown, root: JsonSchema): JsonSchema {
  if (typeof ref !== 'string' || !ref.startsWith('#/$defs/')) {
    throw new Error(`json-schema-lite: unsupported $ref ${String(ref)}`);
  }
  const name = ref.slice('#/$defs/'.length);
  const defs = root['$defs'] as Record<string, JsonSchema> | undefined;
  const target = defs?.[name];
  if (target === undefined) throw new Error(`json-schema-lite: $defs/${name} is not defined`);
  return target;
}

/** Every issue `value` has against `schema` (empty: it validates). */
export function validateJsonSchema(schema: JsonSchema, value: unknown, root: JsonSchema = schema, path = ''): SchemaIssue[] {
  for (const keyword of Object.keys(schema)) {
    if (!KNOWN_KEYWORDS.has(keyword)) throw new Error(`json-schema-lite: unsupported keyword ${keyword}`);
  }
  if (schema['$ref'] !== undefined) return validateJsonSchema(resolveRef(schema['$ref'], root), value, root, path);

  const issues: SchemaIssue[] = [];
  const type = schema['type'];
  if (type !== undefined) {
    const types = Array.isArray(type) ? (type as string[]) : [type as string];
    if (!types.some((candidate) => typeMatches(value, candidate))) {
      issues.push({ path, message: `must be of type ${types.join(' | ')}` });
      return issues;
    }
  }
  if (schema['enum'] !== undefined && !(schema['enum'] as unknown[]).some((option) => deepEqual(option, value))) {
    issues.push({ path, message: `must be one of ${JSON.stringify(schema['enum'])}` });
  }
  if (schema['const'] !== undefined && !deepEqual(schema['const'], value)) {
    issues.push({ path, message: `must equal ${JSON.stringify(schema['const'])}` });
  }
  if (typeof value === 'string') {
    if (typeof schema['minLength'] === 'number' && value.length < schema['minLength']) {
      issues.push({ path, message: `must be at least ${schema['minLength']} characters` });
    }
    if (typeof schema['pattern'] === 'string' && !new RegExp(schema['pattern'], 'u').test(value)) {
      issues.push({ path, message: `must match ${schema['pattern']}` });
    }
    if (schema['format'] === 'date-time' && !(RFC3339_DATE_TIME.test(value) && !Number.isNaN(Date.parse(value)))) {
      issues.push({ path, message: 'must be an RFC 3339 date-time' });
    }
    if (schema['format'] === 'uri') {
      try {
        new URL(value);
      } catch {
        issues.push({ path, message: 'must be a URI' });
      }
    }
  }
  if (typeof value === 'number' && typeof schema['minimum'] === 'number' && value < schema['minimum']) {
    issues.push({ path, message: `must be at least ${schema['minimum']}` });
  }
  if (Array.isArray(value)) {
    if (typeof schema['minItems'] === 'number' && value.length < schema['minItems']) {
      issues.push({ path, message: `must have at least ${schema['minItems']} items` });
    }
    if (schema['items'] !== undefined) {
      value.forEach((item, index) => issues.push(...validateJsonSchema(schema['items'] as JsonSchema, item, root, `${path}/${index}`)));
    }
  }
  if (jsonType(value) === 'object') {
    const record = value as Record<string, unknown>;
    const properties = (schema['properties'] as Record<string, JsonSchema> | undefined) ?? {};
    for (const name of (schema['required'] as string[] | undefined) ?? []) {
      if (!(name in record)) issues.push({ path, message: `must have required property '${name}'` });
    }
    for (const [name, member] of Object.entries(record)) {
      const property = properties[name];
      if (property !== undefined) {
        issues.push(...validateJsonSchema(property, member, root, `${path}/${name}`));
      } else if (schema['additionalProperties'] === false) {
        issues.push({ path: `${path}/${name}`, message: 'must NOT have additional properties' });
      }
    }
  }
  if (Array.isArray(schema['oneOf'])) {
    const matching = (schema['oneOf'] as JsonSchema[]).filter((option) => validateJsonSchema(option, value, root, path).length === 0);
    if (matching.length !== 1) issues.push({ path, message: `must match exactly one schema in oneOf (matched ${matching.length})` });
  }
  return issues;
}

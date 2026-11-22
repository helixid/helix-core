#!/usr/bin/env node
// Copyright 2026 DgVerse LLP
// Regenerates src/core/schemas/credential-schemas.ts from the three *.schema.json
// files (KYA-OS story F-1). Run after editing a schema: node scripts/sync-credential-schemas.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('../src/core/schemas/', import.meta.url));
const names = [
  ['IDENTITY_CREDENTIAL_SCHEMA', 'identity-credential'],
  ['CAPABILITY_ATTESTATION_SCHEMA', 'capability-attestation'],
  ['DELEGATION_HOP_SCHEMA', 'delegation-hop'],
];
let out = `// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// GENERATED from the three *.schema.json files beside it (KYA-OS story F-1) so the
// published package carries the schemas without a JSON import. Regenerate with
// \`node scripts/sync-credential-schemas.mjs\`; tests/unit/core/credentials/schemas.test.ts
// fails when the two drift. Do not hand-edit.

import type { JsonSchema } from "../credentials/json-schema.js";

`;
for (const [constant, file] of names) {
  const schema = JSON.parse(readFileSync(`${dir}${file}.schema.json`, 'utf8'));
  out += `/** \`src/core/schemas/${file}.schema.json\` */\nexport const ${constant}: JsonSchema = ${JSON.stringify(schema, null, 2)} as const;\n\n`;
}
writeFileSync(`${dir}credential-schemas.ts`, out);
console.log('credential-schemas.ts regenerated');

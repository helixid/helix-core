// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

// KYA-OS Entity Cards (story C-A): schema, builder, discovery, verification, projection.
export * from './schema.js';
export * from './build.js';
export * from './chain.js';
export * from './verify.js';
export * from './resolve.js';
export * from './projection.js';
export * from './status-list-checker.js';
export { KYA_OS_CARD_SCHEMA } from './card-schema.js';
// Not re-exported as validateJsonSchema: F-1's credentials module owns that name, and its evaluator
// refuses the card schema's `minimum`. The card's lite evaluator is reached through validateEntityCard.
export { validateJsonSchema as validateCardJsonSchema, type SchemaIssue } from './json-schema-lite.js';

#!/usr/bin/env node
// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0
// `helix-audit` entry point; the command itself is `runAuditCli` in audit.ts.
import { runAuditCli } from './audit.js';

process.exitCode = await runAuditCli(process.argv.slice(2));

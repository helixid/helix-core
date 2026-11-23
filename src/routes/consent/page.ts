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
 * The consent page at `authorizationUrl` (KYA-OS story L3-H point 3): hosted
 * by Helix, branded as the service, showing exactly the grant the service
 * submitted (who, what, until when, and the grant itself), with Approve and
 * Decline. Server-rendered, no script; every value is HTML-escaped.
 */

import type { ConsentPage } from '../../services/consent/consent.service.js';

export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** No script, no framing (clickjacking a consent click), forms only back to this origin. */
export const CONSENT_PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src https:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

const STYLE = `
  body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 0; background: #f6f7f9; color: #1a1d21; }
  main { max-width: 560px; margin: 32px auto; padding: 0 16px; }
  .card { background: #fff; border: 1px solid #e3e6ea; border-radius: 12px; padding: 24px; }
  header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
  header img { width: 40px; height: 40px; border-radius: 8px; }
  h1 { font-size: 20px; margin: 0; }
  ul { padding-left: 20px; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; word-break: break-all; }
  pre { white-space: pre-wrap; background: #f6f7f9; padding: 12px; border-radius: 8px; }
  .actions { display: flex; gap: 12px; margin-top: 20px; }
  button { font-size: 15px; padding: 10px 18px; border-radius: 8px; border: 1px solid #c9ced6; background: #fff; cursor: pointer; }
  button.approve { background: #1f6feb; color: #fff; border-color: #1f6feb; }
  .muted { color: #5b636e; font-size: 13px; }
`;

function shell(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body><main><div class="card">${body}</div></main></body></html>`;
}

export function renderConsentPage(page: ConsentPage, actionBase: string): string {
  const { request } = page;
  const logo = request.display?.logoUrl;
  const scopes = request.grant.allowedAction.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join('');
  const form = (path: string, label: string, extra: string, cls: string): string =>
    `<form method="post" action="${escapeHtml(`${actionBase}/${path}`)}">` +
    `<input type="hidden" name="pageToken" value="${escapeHtml(page.pageToken)}">${extra}` +
    `<button type="submit" class="${cls}" data-testid="consent-${path}">${escapeHtml(label)}</button></form>`;
  return shell(
    `${page.serviceName}: allow ${page.agentName}?`,
    `<header>${logo === undefined ? '' : `<img src="${escapeHtml(logo)}" alt="">`}<h1 data-testid="consent-title">${escapeHtml(page.serviceName)}</h1></header>` +
      `<p><strong data-testid="consent-agent">${escapeHtml(page.agentName)}</strong> asks to act for you at <strong>${escapeHtml(page.serviceName)}</strong> with:</p>` +
      `<ul data-testid="consent-scopes">${scopes}</ul>` +
      `<p>Until <strong data-testid="consent-window">${escapeHtml(request.grant.validUntil)}</strong>. Access renews automatically inside this window; you can withdraw it at ${escapeHtml(page.serviceName)} at any time.</p>` +
      `<details><summary class="muted">The exact grant you sign</summary><pre data-testid="consent-grant">${escapeHtml(JSON.stringify(request.grant, null, 2))}</pre>` +
      `<p class="muted">Agent <code>${escapeHtml(request.agentDid)}</code><br>Service <code>${escapeHtml(request.serviceDid)}</code><br>Digest <code>${escapeHtml(request.grantDigest)}</code></p></details>` +
      `<p class="muted">Approving signs this grant with a key Helix keeps for you at this service only; the service itself cannot sign for you.</p>` +
      `<div class="actions">${form('approve', 'Allow', `<input type="hidden" name="grantDigest" value="${escapeHtml(request.grantDigest)}">`, 'approve')}${form('deny', 'Decline', '', 'deny')}</div>`,
  );
}

export function renderConsentOutcome(title: string, message: string, testId: string): string {
  return shell(title, `<h1 data-testid="${escapeHtml(testId)}">${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`);
}

// Scopes are free text: any characters except whitespace and commas, which
// separate them -- "a,b, cd" is the three scopes a, b and cd. A scope is
// compared exactly, case and all, so `calendar.events`, `read:orders` and
// `https://www.googleapis.com/auth/gmail.readonly` are all valid as given.

/** Any run of whitespace and commas splits scopes. */
export const SCOPE_SEPARATOR = /[\s,]+/;
export const MAX_SCOPE_LENGTH = 255;
/** Per agent credential or service; keeps credentials a bounded size. */
export const MAX_SCOPES = 50;

/** Splits on SCOPE_SEPARATOR and drops empty pieces and repeats, keeping first-seen order. */
export function parseScopes(input: string | readonly string[]): string[] {
  const pieces = (typeof input === 'string' ? [input] : input).flatMap((item) => item.split(SCOPE_SEPARATOR));
  return [...new Set(pieces.filter((piece) => piece.length > 0))];
}

/** Why `scopes` is not a valid scope list, or null when it is. Does not require it to be non-empty. */
export function findScopeProblem(scopes: readonly unknown[]): string | null {
  if (scopes.length > MAX_SCOPES) return `at most ${MAX_SCOPES} scopes are allowed`;
  for (const scope of scopes) {
    if (typeof scope !== 'string' || scope.length === 0) return 'a scope must be a non-empty string';
    if (/[\s,]/.test(scope)) return `scope "${scope}" contains whitespace or a comma, which separate scopes`;
    if (scope.length > MAX_SCOPE_LENGTH) return `scope "${scope.slice(0, 40)}…" is longer than ${MAX_SCOPE_LENGTH} characters`;
  }
  return null;
}

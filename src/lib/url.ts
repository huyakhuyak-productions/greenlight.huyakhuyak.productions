// The scheme is bounded at 32 characters — RFC-registered schemes are well
// under that (`chrome-extension` is the longest commonly-seen one at 16
// chars). Without the bound, long alphabetic input like a code paste with no
// `://` triggers O(n²) backtracking: at every position the engine greedily
// consumes to end of input via `[a-z0-9+\-.]*`, fails to find `:`, then
// rewinds one character at a time while `matchAll` advances the global
// cursor. The cap turns each candidate position into O(1) work.
const URL_RE = /[a-z][a-z0-9+\-.]{0,32}:\/\/[^\s)\]"'<>]+/gi;

export interface UrlOccurrence {
  raw: string;
  start: number;
  end: number;
  host: string;
  hostStart: number;
  hostEnd: number;
}

export function hostOf(input: string): { host: string; start: number; end: number } | null {
  const m = input.match(/^[a-z][a-z0-9+\-.]{0,32}:\/\/([^/?#\s]+)/i);
  if (!m || m.index == null) return null;
  const schemeAndSlashes = m[0].length - m[1].length;
  return { host: m[1], start: m.index + schemeAndSlashes, end: m.index + m[0].length };
}

export function extractUrls(input: string): UrlOccurrence[] {
  const out: UrlOccurrence[] = [];
  for (const m of input.matchAll(URL_RE)) {
    if (m.index == null) continue;
    const raw = m[0];
    const host = hostOf(raw);
    if (!host) continue;
    out.push({
      raw,
      start: m.index,
      end: m.index + raw.length,
      host: host.host,
      hostStart: m.index + host.start,
      hostEnd: m.index + host.end,
    });
  }
  return out;
}

// Returns the first http(s) URL embedded in `evidence`, or null.
//
// Used by the UI layer to pull the URL out of a pipe-to-shell finding's
// evidence so it can offer a "Scan this script" affordance. Restricted to
// http/https — `file://`, `ftp://`, etc. cannot be fetched from a browser
// tab, and offering to scan them would lie about what the click does.
export function extractFirstFetchedUrl(evidence: string): string | null {
  for (const m of evidence.matchAll(URL_RE)) {
    const raw = m[0];
    if (/^https?:\/\//i.test(raw)) return stripTrailingPunctuation(raw);
  }
  return null;
}

// URLs in shell evidence often pick up surrounding shell punctuation that
// isn't part of the URL itself: closing quotes/backticks already excluded by
// the regex's negated class, but a trailing `;` or `,` from a compound
// command (`curl … | bash;`) sneaks through. Strip them off the right edge.
function stripTrailingPunctuation(url: string): string {
  return url.replace(/[.,;:!?]+$/, '');
}

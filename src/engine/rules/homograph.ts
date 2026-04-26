import type { Finding, Rule } from '../types';
import { findConfusables, hasSuspiciousMixedScript, hostOf, scriptsIn } from '../../lib/unicode';
import { isShortener } from '../../data/shorteners';

const URL_RE = /[a-z][a-z0-9+\-.]*:\/\/[^\s)\]"'<>]+/gi;

interface UrlOccurrence {
  raw: string;
  start: number;
  end: number;
  host: string;
  hostStart: number;
  hostEnd: number;
}

function extractUrls(input: string): UrlOccurrence[] {
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
      hostStart: m.index + (host.start - 0),
      hostEnd: m.index + (host.end - 0),
    });
  }
  return out;
}

export const homographRule: Rule = {
  id: 'homograph',
  category: 'homograph',
  appliesTo: ['command', 'url'],
  run(input) {
    const findings: Finding[] = [];

    const urls = extractUrls(input);
    for (const url of urls) {
      const scripts = scriptsIn(url.host);
      const confusables = findConfusables(url.host);
      // Confusables only matter when the host MIXES scripts. A pure-Cyrillic
      // host (e.g. яндекс.рф) is not a homograph attack — it is the user's
      // intended Cyrillic domain.
      const isMixedWithLatin = scripts.has('Latin') && scripts.size > 1;
      if (isMixedWithLatin && confusables.length > 0) {
        const c = confusables[0];
        const cpStart = url.hostStart + c.index;
        findings.push({
          ruleId: 'homograph.confusable_codepoint',
          category: 'homograph',
          severity: 'block',
          title: 'Hostname contains a lookalike character',
          message: `The host "${url.host}" contains a non-ASCII character that resembles "${c.lookalike}". This is the canonical homograph attack — the URL looks legitimate to a reader but resolves to a different domain.`,
          evidence: url.host,
          span: [cpStart, cpStart + c.codepoint.length],
          remediation: 'Retype the URL by hand using only ASCII characters, or copy the canonical URL from a known-good bookmark.',
        });
      } else if (hasSuspiciousMixedScript(url.host)) {
        findings.push({
          ruleId: 'homograph.mixed_script',
          category: 'homograph',
          severity: 'block',
          title: 'Hostname mixes writing systems',
          message: `The host "${url.host}" contains characters from more than one script (e.g. Latin and Cyrillic). Legitimate domains rarely do this.`,
          evidence: url.host,
          span: [url.hostStart, url.hostEnd],
          remediation: 'Verify the canonical hostname before fetching anything from it.',
        });
      }

      if (/(^|\.)xn--/i.test(url.host)) {
        findings.push({
          ruleId: 'homograph.punycode',
          category: 'homograph',
          severity: 'warn',
          title: 'Punycode-encoded hostname',
          message: `The host "${url.host}" is punycode-encoded. Some attacks rely on punycode to hide a non-Latin lookalike domain.`,
          evidence: url.host,
          span: [url.hostStart, url.hostEnd],
          remediation: 'Decode the punycode (e.g. via an IDN converter) and check whether the visible form is suspicious.',
        });
      }

      if (isShortener(url.host)) {
        findings.push({
          ruleId: 'homograph.shortener',
          category: 'homograph',
          severity: 'warn',
          title: 'Shortened URL hides its destination',
          message: `${url.host} is a URL shortener. You cannot see where this link actually leads from the URL alone.`,
          evidence: url.host,
          span: [url.hostStart, url.hostEnd],
          remediation: 'Resolve the shortener (e.g. with `curl -sIL <url>`) before fetching any content from it.',
        });
      }
    }

    return findings;
  },
};

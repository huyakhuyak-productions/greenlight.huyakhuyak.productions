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
  run(input, kind) {
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

    // Cyrillic-anywhere-in-command — broader net than the URL-host detection
    // above. The URL pass only fires on mixed-script hosts (Latin + Cyrillic);
    // a standalone Cyrillic letter elsewhere in the command (an argument, a
    // path, a string literal) still warrants attention because Cyrillic
    // letters are the canonical Latin-lookalike vector. Warn-level: legitimate
    // pure-Cyrillic input does exist (filenames, git messages), but the bar
    // for *any* Cyrillic in a shell snippet is low enough to want a nudge.
    //
    // Skip codepoints that fall inside a URL host the URL pass already
    // inspected — those are either already flagged as block (mixed-script)
    // or deliberately allowed (pure Cyrillic, e.g. яндекс.рф). Either way,
    // re-flagging them here is duplicate noise.
    const CYRILLIC_RE = /\p{Script=Cyrillic}/gu;
    if (kind === 'command') {
      for (const m of input.matchAll(CYRILLIC_RE)) {
        if (m.index == null) continue;
        const insideUrlHost = urls.some(
          (u) => m.index! >= u.hostStart && m.index! < u.hostEnd,
        );
        if (insideUrlHost) continue;
        const ctxStart = Math.max(0, m.index - 8);
        const ctxEnd = Math.min(input.length, m.index + m[0].length + 8);
        findings.push({
          ruleId: 'homograph.cyrillic_in_command',
          category: 'homograph',
          severity: 'warn',
          title: 'Cyrillic character in shell command',
          message:
            'A Cyrillic codepoint is present in this command. Cyrillic letters often look identical to Latin (e.g. "с" U+0441 vs "c" U+0063) and are commonly used to smuggle a different host, path, or argument into what appears to be a familiar command.',
          evidence: input.slice(ctxStart, ctxEnd),
          span: [m.index, m.index + m[0].length],
          remediation:
            'Retype the command by hand from a trusted source. If the Cyrillic is intentional (e.g. a filename), confirm each non-ASCII character.',
        });
        break;
      }
    }

    return findings;
  },
};

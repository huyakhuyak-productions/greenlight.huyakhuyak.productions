/**
 * Unicode helpers for homograph detection.
 *
 * We avoid shipping the full UTS #39 confusables table (~hundreds of KB) and
 * instead rely on Unicode Script properties for mixed-script detection plus
 * a small curated set of high-impact ASCII-lookalike confusables for the
 * "domain that looks like example.com" attack pattern.
 */

export type Script =
  | 'Latin'
  | 'Cyrillic'
  | 'Greek'
  | 'Han'
  | 'Hiragana'
  | 'Katakana'
  | 'Hangul'
  | 'Arabic'
  | 'Hebrew'
  | 'Common'
  | 'Inherited'
  | 'Other';

const SCRIPT_RANGES: Array<[Script, RegExp]> = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Han', /\p{Script=Han}/u],
  ['Hiragana', /\p{Script=Hiragana}/u],
  ['Katakana', /\p{Script=Katakana}/u],
  ['Hangul', /\p{Script=Hangul}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
];

export function detectScript(ch: string): Script {
  // Common (digits, punctuation) and Inherited (combining marks) don't count
  // toward "mixed script" — they're shared across writing systems.
  if (/\p{Script=Common}/u.test(ch)) return 'Common';
  if (/\p{Script=Inherited}/u.test(ch)) return 'Inherited';
  for (const [name, re] of SCRIPT_RANGES) if (re.test(ch)) return name;
  return 'Other';
}

/**
 * Detect mixed-script confusables in a string. Returns the set of distinct
 * non-Common/Inherited scripts present. A label with both Latin and Cyrillic
 * (or Latin and Greek) is the canonical homograph attack.
 */
export function scriptsIn(text: string): Set<Script> {
  const set = new Set<Script>();
  for (const ch of text) {
    const s = detectScript(ch);
    if (s !== 'Common' && s !== 'Inherited' && s !== 'Other') set.add(s);
  }
  return set;
}

const SUSPICIOUS_MIXES: ReadonlyArray<[Script, Script]> = [
  ['Latin', 'Cyrillic'],
  ['Latin', 'Greek'],
  ['Cyrillic', 'Greek'],
];

export function hasSuspiciousMixedScript(text: string): boolean {
  const scripts = scriptsIn(text);
  for (const [a, b] of SUSPICIOUS_MIXES) {
    if (scripts.has(a) && scripts.has(b)) return true;
  }
  return false;
}

/**
 * Curated map of high-impact non-ASCII codepoints that look like an ASCII
 * letter and are commonly used in domain spoofing. This is a deliberate
 * subset — the full UTS #39 table is too large to ship and most of it covers
 * cases we don't care about (e.g. CJK lookalikes for Latin in body text).
 */
const CONFUSABLE_TO_ASCII: Record<string, string> = {
  // Cyrillic
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  у: 'y',
  х: 'x',
  і: 'i',
  ј: 'j',
  ѕ: 's',
  ԁ: 'd',
  Ꭺ: 'A',
  Е: 'E',
  О: 'O',
  Р: 'P',
  С: 'C',
  Х: 'X',
  // Greek
  α: 'a',
  ο: 'o',
  ρ: 'p',
  ν: 'v',
  Α: 'A',
  Β: 'B',
  Ε: 'E',
  Η: 'H',
  Ι: 'I',
  Κ: 'K',
  Μ: 'M',
  Ν: 'N',
  Ο: 'O',
  Ρ: 'P',
  Τ: 'T',
  Υ: 'Y',
  Χ: 'X',
  Ζ: 'Z',
  // Armenian / Cherokee
  ո: 'n',
  ս: 'u',
  ҝ: 'k',
};

/**
 * Find non-ASCII codepoints in `text` that visually resemble an ASCII letter.
 * Returns offsets into the string.
 */
export function findConfusables(
  text: string,
): Array<{ index: number; codepoint: string; lookalike: string }> {
  const out: Array<{ index: number; codepoint: string; lookalike: string }> = [];
  let idx = 0;
  for (const ch of text) {
    const lookalike = CONFUSABLE_TO_ASCII[ch];
    if (lookalike != null) out.push({ index: idx, codepoint: ch, lookalike });
    idx += ch.length;
  }
  return out;
}


import type { Finding, Rule } from '../types';

// Invisible / near-invisible codepoints that don't carry meaning in regular
// text but can encode bits across characters. terminal-injection already
// covers the ZWSP/ZWNJ/ZWJ/BOM/WORD-JOINER cluster and the Unicode TAG block.
// This rule is the "everything else invisible" net.
//
// - U+00AD          Soft Hyphen
// - U+115F / U+1160 Hangul Choseong / Jungseong Filler
// - U+180E          Mongolian Vowel Separator
// - U+2800          Braille Pattern Blank
// - U+3164          Hangul Filler
// - U+FE00–U+FE0E   Variation Selectors (excluding U+FE0F — emoji presentation;
//                   shipped on iOS/macOS keyboards for ❤️/⚠️/etc., huge FP source)
// - U+E0100–U+E01EF Variation Selectors Supplement
// Single source of truth — written via codepoint escapes so the file content
// stays printable and resistant to copy-paste corruption.
const HIDDEN_CLASS =
  '\\u00AD\\u115F\\u1160\\u180E\\u2800\\u3164\\u{FE00}-\\u{FE0E}\\u{E0100}-\\u{E01EF}';
// eslint-disable-next-line no-misleading-character-class -- detecting these chars is the rule's purpose
const HIDDEN_CHAR = new RegExp(`[${HIDDEN_CLASS}]`, 'u');
// eslint-disable-next-line no-misleading-character-class -- detecting these chars is the rule's purpose
const HIDDEN_CHAR_GLOBAL = new RegExp(`[${HIDDEN_CLASS}]`, 'gu');

const PAYLOAD_THRESHOLD = 6; // a cluster this size is almost never accidental

export const steganographyRule: Rule = {
  id: 'steganography',
  category: 'steganography',
  appliesTo: 'any',
  run(input) {
    const findings: Finding[] = [];

    const first = input.match(HIDDEN_CHAR);
    if (!first || first.index == null) return findings;

    const all = Array.from(input.matchAll(HIDDEN_CHAR_GLOBAL));
    const escalate = all.length >= PAYLOAD_THRESHOLD;

    findings.push({
      ruleId: escalate ? 'steganography.invisible_payload' : 'steganography.invisible_marker',
      category: 'steganography',
      severity: escalate ? 'block' : 'warn',
      title: escalate
        ? `Hidden character payload (${all.length} invisible codepoints)`
        : 'Invisible character in input',
      message: escalate
        ? 'A run of normally-invisible Unicode codepoints is present. This pattern is used to encode covert payloads — text that the eye cannot see but the parser will.'
        : 'A character that renders as nothing (or as a space) is mixed into this input. It can change which file/host/package the command actually targets without you noticing.',
      evidence: input.slice(Math.max(0, first.index - 6), Math.min(input.length, first.index + 8)),
      span: [first.index, first.index + first[0].length],
      remediation:
        'Retype the input by hand from a trusted source. Strip non-printing characters before pasting if you must keep the original.',
    });

    return findings;
  },
};

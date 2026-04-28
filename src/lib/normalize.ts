// Clean up a freshly-pasted blob before it lands in the validator. Pasting
// from rendered web pages (READMEs, blog posts, docs) frequently drags in
// trailing spaces on every line and stretches of blank lines from the source
// markup — both visually noisy and unhelpful for human review of the input.
//
// Detection-safe: we only touch ASCII space, tab, CR, LF. Invisible-Unicode
// threats the engine actually looks for (zero-width space, BOM, bidi
// overrides, Hangul/Mongolian fillers, ANSI escapes, Unicode TAG block) are
// none of those, so this never erases a finding the rules would have caught
// on the raw paste.
//
// Note: `\s` in JS matches U+FEFF (BOM), which terminal-injection flags as a
// zero-width threat — so the outer trim uses an explicit ASCII class, not
// `\s`. Keep it that way.
const TRAILING_WS = /[ \t]+\n/g;
const BLANK_RUNS = /\n{3,}/g;
const OUTER_ASCII_WS = /^[ \t\n]+|[ \t\n]+$/g;

export function normalizePaste(text: string): string {
  return text
    .replace(/\r\n?/g, '\n')
    .replace(TRAILING_WS, '\n')
    .replace(BLANK_RUNS, '\n\n')
    .replace(OUTER_ASCII_WS, '');
}

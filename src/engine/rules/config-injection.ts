import type { Finding, Rule } from '../types';

// High-signal shell constructs that show real shell syntax, not just a single
// punctuation char that happens to overlap (a `&` in a URL query string, a
// `$HOME` placeholder). We require either a `$( … )`/`` ` … ` ``/`&&`/`||`,
// OR `;`/`>`/`<` adjacent to whitespace (real command separator/redirection),
// OR `|` between two non-pipe chars (real pipe, not `||`).
const HIGH_SIGNAL_SHELL = [
  /\$\([^)]*\)/, // command substitution
  /`[^`]*`/, // backtick command substitution
  /&&/, // command chaining
  /\|\|/, // command chaining
  /(?:^|\s);\s*\S/, // statement separator before another command
  /\s>>?\s*\S/, // redirection
  /\s<\s*\S/, // input redirection
  /[^|]\|[^|]/, // single pipe
];

function looksLikeShellInjection(s: string): boolean {
  return HIGH_SIGNAL_SHELL.some((re) => re.test(s));
}

// `sh -c "<cmd>"` and `bash -c "<cmd>"` legitimately want shell syntax in the
// args — that's the entry point's whole job. The MCP shape is
// `{ "command": "sh", "args": ["-c", "<cmd>"] }`, so we look at the sibling
// `command` field, not at args[0].
const SHELL_BIN_RE = /^(?:sh|bash|zsh|dash|ash|ksh|fish|pwsh|powershell)(?:\.exe)?$/i;
function commandIsShell(command: unknown): boolean {
  return typeof command === 'string' && SHELL_BIN_RE.test(command.trim());
}

function findArgsShellInjection(
  input: string,
): { value: string; span: [number, number] } | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    return null;
  }
  // Walk every `args` array we find and check each string.
  return walkForSuspectArg(parsed, input);
}

function walkForSuspectArg(
  node: unknown,
  input: string,
): { value: string; span: [number, number] } | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const inner = walkForSuspectArg(child, input);
      if (inner) return inner;
    }
    return null;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    for (const [key, val] of Object.entries(obj)) {
      if (key === 'args' && Array.isArray(val)) {
        if (commandIsShell(obj.command)) continue; // sh -c "..." — shell syntax expected
        const argStrings = val.filter((v): v is string => typeof v === 'string');
        for (const arg of argStrings) {
          if (looksLikeShellInjection(arg)) {
            return { value: arg, span: locateString(input, arg) };
          }
        }
      } else {
        const inner = walkForSuspectArg(val, input);
        if (inner) return inner;
      }
    }
  }
  return null;
}

// Best-effort span lookup — finds the first occurrence of the JSON-decoded
// string in the source. Falls back to [0, 0] if it can't be located (the value
// might contain escapes that don't survive a substring search).
function locateString(input: string, value: string): [number, number] {
  const idx = input.indexOf(value);
  return idx >= 0 ? [idx, idx + value.length] : [0, 0];
}

// Prompt-injection phrases that show up inside CLAUDE.md / .cursorrules /
// system prompts attackers ship in repos. Curated, not exhaustive — false
// positives on real docs would be the death of this rule, so we keep it to
// phrases that are almost never found in legitimate context.
const PROMPT_INJECTION_PHRASES = [
  /\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)\b/i,
  /\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)\b/i,
  /\bforget\s+(?:everything|all)\s+(?:above|before)\b/i,
  /\bnew\s+(?:system\s+)?(?:instructions?|prompt)s?\s*[:.]/i,
  /\byou\s+are\s+now\s+(?:a\s+|an\s+)?(?:different|new|unrestricted|jailbroken|developer\s+mode)/i,
  /\bsystem\s+prompt\s+(?:override|injection|update|patch)\b/i,
  /\bact\s+as\s+(?:if\s+you\s+are\s+|though\s+you\s+are\s+)?(?:DAN|jailbroken|unrestricted|without\s+restrictions)/i,
];

// Invisible/zero-width and bidi-control codepoints that have no business in a
// human-edited config file. Same set as the steganography rule, deliberately
// duplicated so a single suspicious char inside a config still trips here
// (steganography rule needs ≥6 to escalate to block).
const INVISIBLE_IN_CONFIG_CLASS =
  '\\u200B\\u200C\\u200D\\u2060\\uFEFF\\u202A-\\u202E\\u2066-\\u2069\\u{E0000}-\\u{E007F}';
// eslint-disable-next-line no-misleading-character-class
const INVISIBLE_IN_CONFIG = new RegExp(`[${INVISIBLE_IN_CONFIG_CLASS}]`, 'u');

const REMEDIATION_ARGS =
  'Remove shell metacharacters from the args array. If you really need a shell expression, the entry point should be `sh -c "<command>"` and the command itself goes in a separate string — never smuggled into a normal argv slot.';
const REMEDIATION_PROMPT_INJECTION =
  'A shared rules/instructions file should never contain phrases that try to override the model\'s behaviour. If you didn\'t write this, treat the file as compromised.';
const REMEDIATION_INVISIBLE =
  'A config or prompt file with invisible/bidi codepoints is hiding something from your reviewer. Strip the file to ASCII-only and re-read what was actually meant to be there.';

export const configInjectionRule: Rule = {
  id: 'config-injection',
  category: 'config-injection',
  appliesTo: ['config'],
  run(input) {
    const findings: Finding[] = [];

    // 1. Shell injection inside any `"args": [...]` string. JSON-parse so a
    // `]` inside a string can't truncate the scan, and so each arg is checked
    // independently (a `&` in a URL query string in arg #1 doesn't taint arg #2).
    const suspectArg = findArgsShellInjection(input);
    if (suspectArg) {
      findings.push({
        ruleId: 'config-injection.args_shell_meta',
        category: 'config-injection',
        severity: 'block',
        title: 'Shell injection inside MCP config args',
        message:
          'A string in the args array contains shell syntax (command substitution, redirection, pipes, or chaining). argv slots are not interpreted by a shell, so the only plausible reason for this is an attempt to break out via something downstream that forwards the arg through `sh -c`.',
        evidence: suspectArg.value,
        span: suspectArg.span,
        remediation: REMEDIATION_ARGS,
      });
    }

    // 2. Prompt-injection phrases.
    for (const re of PROMPT_INJECTION_PHRASES) {
      const m = input.match(re);
      if (m && m.index != null) {
        findings.push({
          ruleId: 'config-injection.prompt_injection',
          category: 'config-injection',
          severity: 'block',
          title: 'Prompt-injection phrase in config / rules file',
          message:
            'This file contains a phrase whose only purpose is to override an LLM\'s instructions. If this is a CLAUDE.md, .cursorrules, .windsurfrules or similar shared file, an attacker may have planted it to hijack assistant behaviour for anyone who clones the repo.',
          evidence: m[0],
          span: [m.index, m.index + m[0].length],
          remediation: REMEDIATION_PROMPT_INJECTION,
        });
        break; // one finding is enough — they're all the same category.
      }
    }

    // 3. Invisible / bidi codepoints inside a config blob.
    const invisible = input.match(INVISIBLE_IN_CONFIG);
    if (invisible && invisible.index != null) {
      findings.push({
        ruleId: 'config-injection.invisible_in_config',
        category: 'config-injection',
        severity: 'warn',
        title: 'Invisible or bidi-control codepoint in config',
        message:
          'A config or rules file contains a zero-width, bidi-override, or tag codepoint that does not render. In a CLAUDE.md / .cursorrules / MCP config this is almost always an attempt to smuggle hidden instructions past human review.',
        evidence: `U+${invisible[0].codePointAt(0)?.toString(16).toUpperCase().padStart(4, '0')}`,
        span: [invisible.index, invisible.index + invisible[0].length],
        remediation: REMEDIATION_INVISIBLE,
      });
    }

    return findings;
  },
};

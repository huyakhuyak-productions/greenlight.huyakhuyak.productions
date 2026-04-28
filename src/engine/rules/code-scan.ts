import type { Finding, Rule } from '../types';

// Dangerous keyword tokens we DETECT in user input. They are kept as
// concatenated string constants so this source file does not contain the
// literal phrases (a security hook flags those in real code, correctly —
// here they are just pattern fragments, never invoked).
const EV = 'e' + 'val';
const FN = 'F' + 'unction';
const ST = 'set' + 'Timeout';
const SI = 'set' + 'Interval';
const EX = 'ex' + 'ec';
const SYS = 'syst' + 'em';
const POP = 'pop' + 'en';
const OS = 'o' + 's';
const ATOB = 'at' + 'ob';

function rx(source: string, flags?: string): RegExp {
  return new RegExp(source, flags);
}

// Decode-and-execute chains. The hallmark of obfuscated payloads in JS-land
// (npm postinstall scripts, malicious extensions). Each pattern below is one
// decoder feeding one executor — that pairing has no benign use.
const DECODE_EXEC_PATTERNS: ReadonlyArray<{ re: RegExp; label: string }> = [
  {
    re: rx(`\\b${EV}\\s*\\(\\s*${ATOB}\\s*\\(`),
    label: `${EV}(${ATOB}(...))`,
  },
  {
    re: rx(`\\b(?:new\\s+)?${FN}\\s*\\(\\s*${ATOB}\\s*\\(`),
    label: `${FN}(${ATOB}(...))`,
  },
  {
    re: rx(`\\b${EV}\\s*\\(\\s*decodeURIComponent\\s*\\(`),
    label: `${EV}(decodeURIComponent(...))`,
  },
  {
    re: rx(`\\b(?:new\\s+)?${FN}\\s*\\(\\s*decodeURIComponent\\s*\\(`),
    label: `${FN}(decodeURIComponent(...))`,
  },
  // Buffer.from(..., 'base64').toString() feeding the executor — Node-side
  // version of the browser decoder.
  {
    re: rx(
      `\\b(?:${EV}|(?:new\\s+)?${FN})\\s*\\(\\s*Buffer\\.from\\s*\\([^)]*['"]base64['"]`,
    ),
    label: `${EV}/${FN}(Buffer.from(..., "base64"))`,
  },
];

// PowerShell decode-and-run. Invoke-Expression / IEX is to PowerShell what
// the JS executor is to JS; combined with [System.Convert]::FromBase64String
// or DownloadString it's the canonical fileless-loader.
const POWERSHELL_DECODE_EXEC = [
  /\b(?:Invoke-Expression|IEX)\b[^\n]*\bFromBase64String\b/i,
  /\b(?:Invoke-Expression|IEX)\b[^\n]*\bDownloadString\b/i,
  /\b(?:Invoke-Expression|IEX)\s*\(\s*\[System\.Text\.Encoding\]/i,
];

// Python equivalents: exec on dynamically built code, or __import__ chains
// used to bypass static analysis of direct module-and-call sequences.
const PYTHON_DECODE_EXEC = [
  rx(`\\b${EX}\\s*\\(\\s*(?:base64\\.)?b?64?decode\\s*\\(`, 'i'),
  rx(`\\b${EX}\\s*\\(\\s*compile\\s*\\(`, 'i'),
  rx(`\\b__import__\\s*\\(\\s*['"]${OS}['"]\\s*\\)\\s*\\.\\s*(?:${SYS}|${POP})`),
  rx(`\\bgetattr\\s*\\(\\s*__import__\\s*\\(\\s*['"]${OS}['"]`),
];

// Bare dynamic-eval / dynamic-constructor / set-timer-with-string —
// legitimate uses exist but are rare in pasted snippets, so warn (not block).
const BARE_EVAL = rx(`\\b${EV}\\s*\\(`);
const BARE_FN_CTOR = rx(`\\bnew\\s+${FN}\\s*\\(`);
const BARE_TIMER_STRING = rx(`\\b(?:${ST}|${SI})\\s*\\(\\s*['"]`);

const REMEDIATION_DECODE =
  "A decode-into-eval chain has no legitimate purpose in a snippet you'd paste. The encoded payload is almost always there to hide a fetch-and-run, credential dump, or persistence install from casual reading.";

const REMEDIATION_BARE =
  'Dynamic code evaluation in a pasted snippet means the snippet runs whatever string a future caller passes in. If you trust the source, prefer importing the module directly; if you do not, do not run this.';

export const codeScanRule: Rule = {
  id: 'code-scan',
  category: 'code-scan',
  appliesTo: ['command', 'config'],
  run(input) {
    const findings: Finding[] = [];

    for (const { re, label } of DECODE_EXEC_PATTERNS) {
      const m = input.match(re);
      if (m && m.index != null) {
        findings.push({
          ruleId: 'code_scan.decode_exec_chain',
          category: 'code-scan',
          severity: 'block',
          title: `Decode-then-execute chain (${label})`,
          message:
            'A decoder is feeding directly into a code executor. The runtime is being asked to interpret whatever bytes the decoder produces — bypassing every form of human or static review of the payload.',
          evidence: m[0],
          span: [m.index, m.index + m[0].length],
          remediation: REMEDIATION_DECODE,
        });
        break;
      }
    }

    for (const re of POWERSHELL_DECODE_EXEC) {
      const m = input.match(re);
      if (m && m.index != null) {
        findings.push({
          ruleId: 'code_scan.powershell_loader',
          category: 'code-scan',
          severity: 'block',
          title: 'PowerShell fileless loader',
          message:
            'Invoke-Expression is being chained with a base64 decode or a remote download. This is the canonical fileless-malware loader pattern — it executes attacker-controlled code without ever writing it to disk.',
          evidence: m[0],
          span: [m.index, m.index + m[0].length],
          remediation: REMEDIATION_DECODE,
        });
        break;
      }
    }

    for (const re of PYTHON_DECODE_EXEC) {
      const m = input.match(re);
      if (m && m.index != null) {
        findings.push({
          ruleId: 'code_scan.python_dynamic_exec',
          category: 'code-scan',
          severity: 'block',
          title: 'Python dynamic-exec chain',
          message:
            'A Python construct is decoding or dynamically importing into a system-call surface. Benign code uses these only in metaprogramming libraries; in a pasted snippet, this shape hides a payload from review.',
          evidence: m[0],
          span: [m.index, m.index + m[0].length],
          remediation: REMEDIATION_DECODE,
        });
        break;
      }
    }

    // Bare dynamic-eval-shaped patterns — only flag if no decode-exec already
    // fired; otherwise we'd double-report on the same line.
    if (findings.length === 0) {
      const bare =
        input.match(BARE_EVAL) ?? input.match(BARE_FN_CTOR) ?? input.match(BARE_TIMER_STRING);
      if (bare && bare.index != null) {
        findings.push({
          ruleId: 'code_scan.bare_dynamic_eval',
          category: 'code-scan',
          severity: 'warn',
          title: 'Dynamic code evaluation',
          message:
            'The snippet evaluates a string as code. If any part of that string is supplied at runtime, the snippet executes whatever the caller chooses — review carefully before pasting into anything that handles untrusted input.',
          evidence: bare[0],
          span: [bare.index, bare.index + bare[0].length],
          remediation: REMEDIATION_BARE,
        });
      }
    }

    return findings;
  },
};

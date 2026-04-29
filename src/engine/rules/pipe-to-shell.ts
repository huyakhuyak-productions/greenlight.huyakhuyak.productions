import type { Finding, Rule } from '../types';

const FETCHER =
  '(?:curl|wget|fetch|http|aria2c|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)';
// `iex` and `Invoke-Expression` are PowerShell's eval-of-string. Functionally
// they're the right-hand side of `curl … | iex` — same threat shape as
// `curl … | bash`, just on Windows.
const INTERPRETER =
  '(?:bash|sh|zsh|fish|ksh|dash|ash|python\\d?|ruby|perl|node|deno|bun|php|powershell|pwsh|iex|Invoke-Expression)';
const C_FLAG = '(?:-c|--command|-e|-r|-Command|/c)';

// Privilege / scheduling wrappers that real-world install one-liners stack in
// front of the interpreter on the right-hand side of a pipe. Without these,
// `curl … | sudo -E bash` and `wget … | sudo sh /dev/stdin` (Mail-in-a-Box,
// Calibre) slip past the FETCHER_PIPE_TO_SHELL pattern, which only knew how to
// look for a bare interpreter token after `|`.
const PRIVILEGE_WRAPPER = '(?:sudo|nohup|nice|env|time|exec|setsid|stdbuf)';
// Zero or more wrappers, each optionally followed by short/long flags
// (`sudo -E`, `nice -n 10`). Flags are matched lazily via `\\S+` so we can
// admit `sudo --preserve-env=PATH bash`-style invocations too.
const PRIVILEGE_WRAPPER_PREFIX =
  `(?:${PRIVILEGE_WRAPPER}(?:\\s+(?:-\\S+|--\\S+))*\\s+)*`;

const FETCHER_PIPE_TO_SHELL = new RegExp(
  `\\b${FETCHER}\\b[^\\n|]*(?:\\|\\s*[^|\\n]*?)*\\|\\s*${PRIVILEGE_WRAPPER_PREFIX}${INTERPRETER}\\b`,
  'i',
);

const PROCESS_SUB = new RegExp(`\\b${INTERPRETER}\\b\\s*<\\(\\s*${FETCHER}\\b`, 'i');

const EVAL_SUBSTITUTION = new RegExp(
  `\\b(?:eval|source|\\.)\\b[^\\n]*\\$\\(\\s*${FETCHER}\\b`,
  'i',
);

const BACKTICK_FETCH = new RegExp(`\\b(?:eval|source)\\b[^\\n]*\`\\s*${FETCHER}\\b`, 'i');

// `bash -c "$(curl ...)"` family — the single biggest miss in the original
// rule. POSIX shells, language interpreters, and PowerShell with -Command all
// embed a command substitution whose output is executed verbatim.
// Matches: bash -c "$(curl ...)", sh -c '$(wget ...)', python -c "$(curl ...)",
//          node -e "$(curl ...)", ruby -e `curl ...`, pwsh -Command "$(iwr ...)",
//          cmd /c "$(curl ...)" (PowerShell-on-Windows hosts).
const INTERPRETER_INLINE_FETCH = new RegExp(
  `\\b${INTERPRETER}\\b\\s+${C_FLAG}\\b[^\\n]*?[\\$\`]\\(?\\s*${FETCHER}\\b`,
  'i',
);

// Same threat shape, fed via a here-string instead of -c.
// Matches: bash <<< "$(curl ...)", zsh <<< `wget -qO- ...`
const HERESTRING_FETCH = new RegExp(
  `\\b${INTERPRETER}\\b[^\\n]*<<<[^\\n]*?[\\$\`]\\(?\\s*${FETCHER}\\b`,
  'i',
);

// PowerShell idiom: Invoke-Expression of any networked download. `iex` and
// `Invoke-Expression` are the same thing; targets include irm/iwr aliases,
// curl/wget (also aliased to Invoke-WebRequest in PS), and explicit
// .DownloadString / .DownloadFile method calls on WebClient instances.
const POWERSHELL_IEX_OF_FETCH = new RegExp(
  `\\b(?:iex|Invoke-Expression)\\b[\\s(]+["']?\\(?\\s*(?:${FETCHER}\\b|[^\\n]*?\\.(?:DownloadString|DownloadFile)\\b)`,
  'i',
);

// Save-then-execute on the same logical line. Brief disk persistence offers
// no real inspection — anyone running `curl -o x && bash x` is not reading
// `x` between the two statements. Warn (not block): occasionally legitimate
// for vetted release artifacts; we still want a nudge.
const SAVE_THEN_EXEC = new RegExp(
  `\\b${FETCHER}\\b[^\\n]*?\\s-[oO]\\s+(\\S+)[^\\n]*?(?:&&|;|\\|\\|)[^\\n]*?\\b${INTERPRETER}\\b\\s+\\1\\b`,
  'i',
);

// `-O` (capital) tells curl to infer the filename from the URL's basename, so
// there is no filename argument to capture. The threat shape is identical to
// `-o name`: download, then immediately invoke an interpreter on the saved
// file. We warn whenever an `-O` fetch is followed by an interpreter
// invocation on the same line, regardless of whether the basename can be
// matched syntactically.
//
// Real installers cluster short flags (`curl -OL`, `curl -fsSLO`,
// `wget -nvO-`), so we match `O` anywhere inside a `-` flag cluster — not
// just as a standalone `-O`. Case-insensitive via the `i` flag, so `-fsslo`
// and `-O` are both caught. The trailing `\\b` keeps the cluster from
// extending into the next token.
const SAVE_O_INFERRED_THEN_EXEC = new RegExp(
  `\\b${FETCHER}\\b[^\\n]*?\\s-[a-zA-Z]*O[a-zA-Z]*\\b[^\\n]*?(?:&&|;|\\|\\|)[^\\n]*?\\b${INTERPRETER}\\b\\s+\\S+`,
  'i',
);

function findMatch(
  input: string,
  re: RegExp,
): { evidence: string; span: [number, number] } | null {
  const m = input.match(re);
  if (!m || m.index == null) return null;
  return { evidence: m[0], span: [m.index, m.index + m[0].length] };
}

const REMEDIATION =
  'Download the script first, inspect it (`less ./install.sh`), then run it explicitly. Never trust a remote pipeline that runs unread code.';

export const pipeToShellRule: Rule = {
  id: 'pipe_to_shell.fetch_to_interpreter',
  category: 'pipe-to-shell',
  appliesTo: ['command'],
  run(input) {
    const findings: Finding[] = [];

    const direct = findMatch(input, FETCHER_PIPE_TO_SHELL);
    if (direct) {
      findings.push({
        ruleId: 'pipe_to_shell.fetch_to_interpreter',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Remote download piped to a shell',
        message:
          'A network fetch is being piped directly into a shell or interpreter. The script can change between when you read it and when you run it, and you cannot inspect it before execution.',
        evidence: direct.evidence,
        span: direct.span,
        remediation: REMEDIATION,
      });
    }

    const procsub = findMatch(input, PROCESS_SUB);
    if (procsub) {
      findings.push({
        ruleId: 'pipe_to_shell.process_substitution',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Process substitution executes a remote fetch',
        message:
          'Bash process substitution `<(curl ...)` runs the fetched output as if it were a local file. The remote contents are never persisted or inspected.',
        evidence: procsub.evidence,
        span: procsub.span,
        remediation: REMEDIATION,
      });
    }

    const ev = findMatch(input, EVAL_SUBSTITUTION) ?? findMatch(input, BACKTICK_FETCH);
    if (ev) {
      findings.push({
        ruleId: 'pipe_to_shell.eval_of_fetch',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Remote fetch evaluated as code',
        message:
          'A network fetch is being passed to `eval`, `source`, or backticks. The downloaded text is executed as shell code without inspection.',
        evidence: ev.evidence,
        span: ev.span,
        remediation: REMEDIATION,
      });
    }

    const inline = findMatch(input, INTERPRETER_INLINE_FETCH);
    if (inline) {
      findings.push({
        ruleId: 'pipe_to_shell.inline_interpreter_fetch',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Interpreter executes a remote fetch via -c / -e',
        message:
          'An interpreter is being invoked with `-c` / `-e` / `-Command` and a command substitution that performs a network fetch. The fetched text is run verbatim — same threat shape as `curl … | bash`, just disguised by the wrapper.',
        evidence: inline.evidence,
        span: inline.span,
        remediation: REMEDIATION,
      });
    }

    const herestring = findMatch(input, HERESTRING_FETCH);
    if (herestring) {
      findings.push({
        ruleId: 'pipe_to_shell.herestring_fetch',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'Remote fetch fed to a shell via here-string',
        message:
          'A here-string (`<<<`) feeds a command-substituted network fetch into a shell. The downloaded bytes execute without ever being written to disk or inspected.',
        evidence: herestring.evidence,
        span: herestring.span,
        remediation: REMEDIATION,
      });
    }

    const psIex = findMatch(input, POWERSHELL_IEX_OF_FETCH);
    if (psIex) {
      findings.push({
        ruleId: 'pipe_to_shell.powershell_iex_of_fetch',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'PowerShell evaluates a remote download',
        message:
          'PowerShell `Invoke-Expression` (alias `iex`) is executing the result of a network download. This is the canonical pattern used by drop-and-run loaders and credential stealers.',
        evidence: psIex.evidence,
        span: psIex.span,
        remediation:
          'Save the script first (`Invoke-WebRequest -Uri … -OutFile script.ps1`), inspect it, then run it explicitly. Never pipe a download straight into `iex`.',
      });
    }

    const saveExec =
      findMatch(input, SAVE_THEN_EXEC) ?? findMatch(input, SAVE_O_INFERRED_THEN_EXEC);
    if (saveExec) {
      findings.push({
        ruleId: 'pipe_to_shell.save_then_execute',
        category: 'pipe-to-shell',
        severity: 'warn',
        title: 'Download immediately followed by execution',
        message:
          'A script is downloaded and run on the same line. The brief disk hop offers no real inspection step; functionally identical to piping the fetch into a shell.',
        evidence: saveExec.evidence,
        span: saveExec.span,
        remediation:
          'Split the download from the execution. Run a checksum or read the file before invoking it.',
      });
    }

    return findings;
  },
};

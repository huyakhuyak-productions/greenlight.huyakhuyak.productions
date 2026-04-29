import type { Finding, Rule } from '../types';

// Plain `..` traversal targeting OS-sensitive files. The `{2,8}` upper bound
// stops the JS engine from retrying ever-deeper traversal counts on
// adversarial input (e.g. `'../'.repeat(8000) + 'XX'`). Eight levels of `..`
// are already deeper than any legitimate relative-import path; the threat
// signature is the *combination* with a sensitive target, not the depth.
const TRAVERSAL_TO_SENSITIVE =
  /(?:\.{2}\/){2,8}(?:etc\/(?:passwd|shadow|hosts|sudoers|crontab|ssh\/[^\s]+)|root\/[^\s]*|proc\/[^\s]*|home\/[^/\s]+\/\.(?:ssh|aws|kube|netrc|gnupg)\/[^\s]*)/i;

// Windows backslash variant — `..\..\windows\...` etc. Less common in
// shell-paste contexts but still seen in zip/tar entries and CMD payloads.
const TRAVERSAL_BACKSLASH_WINDOWS =
  /(?:\.{2}\\){2,8}(?:windows\\(?:system32|win\.ini)|users\\[^\\\s]+\\(?:\.ssh|appdata))/i;

// URL-encoded `..` — `%2e%2e%2f` and `%2E%2E%5C`. Three or more occurrences
// in a row is the normal "encoded traversal" shape; one is too noisy because
// `%2e` legitimately appears in URLs.
const URL_ENCODED_TRAVERSAL = /(?:%2[eE]){2}(?:%2[fF]|%5[cC]|\/|\\)(?:[^/\\]*(?:%2[eE]){2}(?:%2[fF]|%5[cC]|\/|\\))+/;

// Double-URL-encoded — `%252e%252e%252f`. One layer of `%25` already means
// the path was deliberately encoded twice; combined with `%2e%2e` shape it's
// a classic WAF-bypass pattern.
const DOUBLE_URL_ENCODED_TRAVERSAL = /(?:%25%32%65|%252[eE]){2}(?:%252[fF]|%255[cC]|\/|\\)/;

// Null byte in a path — historic PHP/CGI extension-truncation trick. Modern
// runtimes mostly reject these, but they show up in payload strings; their
// presence at all in a paste is a strong signal.
const NULL_BYTE = /\x00/;

// Non-ASCII codepoints sitting inside what looks like a unix-shaped path.
// Whole-snippet Unicode is fine (people paste comments, prose, JSON values);
// non-ASCII in `/usr/bin/<cyrillic-c>at`-style paths is the homograph attack
// at the path level.
const NON_ASCII_IN_PATH = /(?:^|\s)\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]*[^\x00-\x7F\s][\S]*/;

const REMEDIATION_TRAVERSAL =
  'Path-traversal sequences in a pasted command or config target files outside the directory the command appears to operate on. If the source is a tar/zip extraction step, decompress with a tool that rejects relative parents (`tar --strip-components=N`, `unzip` with explicit `-d` and post-extract validation).';

const REMEDIATION_ENCODED =
  'URL-encoded `..` sequences are the standard way to slip path traversal past WAFs and naive substring filters. There is no reason to encode `..` in a URL you would paste into a shell — the receiving server decodes it before applying any filesystem rule.';

const REMEDIATION_NULL =
  'A null byte inside a path is exclusively a payload-engineering trick (extension truncation, log injection). Strip the byte and use the intended path.';

const REMEDIATION_NON_ASCII =
  'A non-ASCII codepoint inside a unix-shaped path is the homograph attack applied to filenames. The visible name resolves to a different file (or no file) than what you read.';

export const pathAnalysisRule: Rule = {
  id: 'path-analysis',
  category: 'path-analysis',
  appliesTo: 'any',
  run(input) {
    const findings: Finding[] = [];

    const trav =
      input.match(TRAVERSAL_TO_SENSITIVE) ?? input.match(TRAVERSAL_BACKSLASH_WINDOWS);
    if (trav && trav.index != null) {
      findings.push({
        ruleId: 'path_analysis.traversal_to_sensitive',
        category: 'path-analysis',
        severity: 'block',
        title: 'Directory traversal targeting a sensitive path',
        message:
          'The path climbs out of the apparent working directory and lands inside an OS-sensitive area (system credential files, SSH keys, shadow, registry hives). This shape is the canonical "read anything on the host" payload.',
        evidence: trav[0],
        span: [trav.index, trav.index + trav[0].length],
        remediation: REMEDIATION_TRAVERSAL,
      });
    }

    const enc =
      input.match(DOUBLE_URL_ENCODED_TRAVERSAL) ?? input.match(URL_ENCODED_TRAVERSAL);
    if (enc && enc.index != null) {
      findings.push({
        ruleId: 'path_analysis.encoded_traversal',
        category: 'path-analysis',
        severity: 'block',
        title: 'URL-encoded path-traversal sequence',
        message:
          'The string contains percent-encoded `..` segments. Almost every legitimate URL leaves `..` literal — encoding it is the standard way to slip past upstream filters that compare strings before the server decodes them.',
        evidence: enc[0],
        span: [enc.index, enc.index + enc[0].length],
        remediation: REMEDIATION_ENCODED,
      });
    }

    const nul = input.match(NULL_BYTE);
    if (nul && nul.index != null) {
      findings.push({
        ruleId: 'path_analysis.null_byte',
        category: 'path-analysis',
        severity: 'block',
        title: 'Null byte in input',
        message:
          'A NUL (0x00) byte is in the input. Outside binary file editing this byte is exclusively a path-truncation or log-injection payload — there is no shell, URL, or config use that needs it.',
        evidence: '\\x00',
        span: [nul.index, nul.index + 1],
        remediation: REMEDIATION_NULL,
      });
    }

    const nonAscii = input.match(NON_ASCII_IN_PATH);
    if (nonAscii && nonAscii.index != null) {
      findings.push({
        ruleId: 'path_analysis.non_ascii_path',
        category: 'path-analysis',
        severity: 'warn',
        title: 'Non-ASCII codepoint in a unix-shaped path',
        message:
          'A unix-style absolute path contains a non-ASCII codepoint. In legitimate paths this is rare and mostly unintentional; in malicious snippets it is a homograph trick — the visible filename does not match the bytes the kernel resolves.',
        evidence: nonAscii[0].trim(),
        span: [nonAscii.index, nonAscii.index + nonAscii[0].length],
        remediation: REMEDIATION_NON_ASCII,
      });
    }

    return findings;
  },
};

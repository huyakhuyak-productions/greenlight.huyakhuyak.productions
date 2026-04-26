import type { Finding, Rule } from '../types';

// Variables whose only purpose is to inject code at process start-up. These
// are nearly never set legitimately from a pasted snippet, so any assignment
// is a block.
const ALWAYS_HIJACK_VARS = [
  'LD_PRELOAD',
  'LD_AUDIT',
  'DYLD_INSERT_LIBRARIES',
  'PYTHONSTARTUP',
  'PERL5OPT',
  'PROMPT_COMMAND',
  'BASH_ENV',
  'ENV',
];

// Variables that have a real, common, benign use — extending a search/lib path,
// raising Node's heap, customising the prompt — but which can also be weaponised
// to inject code. Block only when the value itself looks shell-y or fetches code.
const SUSPECT_HIJACK_VARS = [
  'LD_LIBRARY_PATH',
  'DYLD_LIBRARY_PATH',
  'DYLD_FALLBACK_LIBRARY_PATH',
  'PYTHONPATH',
  'PERL5LIB',
  'NODE_OPTIONS',
  'PS1',
];

const ALWAYS_HIJACK_RE = new RegExp(
  `\\b(?:export\\s+)?(${ALWAYS_HIJACK_VARS.join('|')})\\s*=\\s*("[^"]*"|'[^']*'|\\S+)`,
);

const SUSPECT_HIJACK_RE = new RegExp(
  `\\b(?:export\\s+)?(${SUSPECT_HIJACK_VARS.join('|')})\\s*=\\s*("[^"]*"|'[^']*'|\\S+)`,
);

// Indicators that a variable's *value* is doing something beyond a path/flag
// list — fetching code, running a shell, decoding, or pointing at a writable
// scratch dir.
const VALUE_LOOKS_HIJACKED = [
  /[;`]|\$\(|&&|\|\|/, // shell syntax
  /\bcurl\b|\bwget\b/i, // fetch
  /\bbase64\b/i, // decode
  /\bsh\b|\bbash\b|\bzsh\b|\beval\b|\bexec\b/i, // shell exec
  /\/tmp\/|\/var\/tmp\//i, // writable scratch
];

function valueIsSuspect(value: string): boolean {
  return VALUE_LOOKS_HIJACKED.some((re) => re.test(value));
}

// PATH=<thing>:$PATH (or :PATH) where <thing> looks like a writable, suspect
// dir — /tmp, /var/tmp, the current dir (.), $HOME hot-dir, etc.
const PATH_PREPEND_SUSPECT =
  /\b(?:export\s+)?PATH\s*=\s*(?:"|')?(?:\.|\.\/|\/tmp|\/var\/tmp|~\/[^:"']*|\$HOME[^:"']*)(?::|"|')/;

// Proxy exports — every outbound HTTP request from this shell passes through
// whatever the value points at. We capture the assignment, then decide whether
// the host is local in code (regex lookahead is fragile here because of the
// optional scheme).
// Match the four canonical proxy-var names case-insensitively. `NO_PROXY` is
// deliberately excluded — it's a do-not-proxy *allowlist*, not a redirector.
const PROXY_VAR_ASSIGN =
  /\b(?:export\s+)?(http_proxy|https_proxy|all_proxy|ftp_proxy)\s*=\s*"?([^\s"']+)/i;

const LOCAL_PROXY_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

function proxyTargetIsLocal(value: string): boolean {
  const noScheme = value.replace(/^https?:\/\//i, '');
  // Strip path, then port. IPv6 in brackets: `[::1]:8080`.
  const hostPart = noScheme.split('/')[0];
  const host = hostPart.startsWith('[')
    ? hostPart.slice(1, hostPart.indexOf(']'))
    : hostPart.split(':')[0];
  return LOCAL_PROXY_HOSTS.has(host);
}

const REMEDIATION_HIJACK =
  'These variables modify how every subsequent program starts. A pasted command should not set them — almost always this is a process-injection attempt.';

const REMEDIATION_PATH =
  'Prepending /tmp, the current directory, or a $HOME-relative path to $PATH means an attacker can ship an executable with the same name as a real binary and intercept future commands.';

const REMEDIATION_PROXY =
  'A proxy export reroutes outbound requests through whatever the attacker controls. They can read or modify everything you fetch in this shell.';

export const environmentRule: Rule = {
  id: 'environment',
  category: 'environment',
  appliesTo: ['command', 'config'],
  run(input) {
    const findings: Finding[] = [];

    const hijack = input.match(ALWAYS_HIJACK_RE);
    if (hijack && hijack.index != null) {
      findings.push({
        ruleId: 'environment.process_hijack_var',
        category: 'environment',
        severity: 'block',
        title: `Process-hijack environment variable (${hijack[1]})`,
        message:
          'This variable controls how the dynamic linker, interpreter, or shell loads code at start-up. Setting it from a pasted snippet substitutes attacker-supplied code into every program that runs afterwards.',
        evidence: hijack[0],
        span: [hijack.index, hijack.index + hijack[0].length],
        remediation: REMEDIATION_HIJACK,
      });
    }

    // Suspect-vars: only flag when the value carries shell syntax / fetches /
    // scratch dirs. Stops `PYTHONPATH=$PYTHONPATH:./src`-style benign pastes
    // from blocking, while still catching `NODE_OPTIONS="--require /tmp/x.js"`.
    const suspect = input.match(SUSPECT_HIJACK_RE);
    if (suspect && suspect.index != null && valueIsSuspect(suspect[2])) {
      findings.push({
        ruleId: 'environment.process_hijack_var',
        category: 'environment',
        severity: 'block',
        title: `Suspicious value in ${suspect[1]}`,
        message:
          'This variable has a legitimate use, but its value contains shell syntax, a fetch, or a writable-scratch path. That shape only makes sense if something is being injected at process start-up.',
        evidence: suspect[0],
        span: [suspect.index, suspect.index + suspect[0].length],
        remediation: REMEDIATION_HIJACK,
      });
    }

    const pp = input.match(PATH_PREPEND_SUSPECT);
    if (pp && pp.index != null) {
      findings.push({
        ruleId: 'environment.path_prepend_suspect',
        category: 'environment',
        severity: 'warn',
        title: 'Suspicious directory prepended to $PATH',
        message:
          'A writable or untrusted directory is being placed ahead of $PATH. The next command you run that shares a name with a binary in that directory will run the impostor instead.',
        evidence: pp[0],
        span: [pp.index, pp.index + pp[0].length],
        remediation: REMEDIATION_PATH,
      });
    }

    const proxy = input.match(PROXY_VAR_ASSIGN);
    if (proxy && proxy.index != null && !proxyTargetIsLocal(proxy[2])) {
      findings.push({
        ruleId: 'environment.proxy_to_remote',
        category: 'environment',
        severity: 'warn',
        title: 'Outbound HTTP proxy pointed at a remote host',
        message:
          'Setting http_proxy/https_proxy/all_proxy reroutes every outbound request from this shell. Pointed at a non-loopback host, the proxy operator sees and can rewrite all your traffic.',
        evidence: proxy[0],
        span: [proxy.index, proxy.index + proxy[0].length],
        remediation: REMEDIATION_PROXY,
      });
    }

    return findings;
  },
};

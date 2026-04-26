import type { Finding, Rule } from '../types';
import { TYPOSQUATS } from '../../data/typosquats';

// Package install commands the rule cares about. Subcommand is required so
// `pip install https://…` is recognised — `pip` alone would otherwise capture
// "install" as the target.
const INSTALLERS =
  '(?:pip3?\\s+install|pipx\\s+install|uv\\s+(?:pip\\s+install|add)|poetry\\s+add|npm\\s+(?:install|i)|pnpm\\s+add|yarn\\s+add|bun\\s+add|gem\\s+install|go\\s+install|cargo\\s+install)';

// `<installer> <pkg-or-url>` — capture only the first non-flag argument.
// Flags can be `-X`, `--foo`, `--foo=bar`, or `--foo bar` (space-separated
// value, used by pip's `--index-url URL`). The value-bearing-flag list keeps
// us from greedily consuming a real package name as a flag value.
const VALUE_BEARING_LONG_FLAGS = '(?:index-url|extra-index-url|registry|find-links|prefix|target)';
const INSTALL_AND_TARGET = new RegExp(
  `\\b${INSTALLERS}((?:\\s+(?:--${VALUE_BEARING_LONG_FLAGS}(?:\\s+|=)\\S+|--?\\S+(?:=\\S*)?))*)\\s+(\\S+)`,
  'i',
);

// Custom registries / index URLs.
const CUSTOM_REGISTRY =
  /(?:--index-url|--extra-index-url|--registry)(?:[\s=])(?:"|')?(https?:\/\/[^\s"']+)/i;

// Exact-match allowlist — host must be one of these, not just *contain* the
// substring. Without exact-match, `npmjs.org.evil.com` would defeat the
// allowlist.
const DEFAULT_REGISTRY_HOSTS = new Set([
  'npmjs.org',
  'npmjs.com',
  'registry.npmjs.org',
  'registry.npmjs.com',
  'pypi.org',
  'pypi.python.org',
  'files.pythonhosted.org',
  'rubygems.org',
  'crates.io',
]);

function isDefaultRegistry(url: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return DEFAULT_REGISTRY_HOSTS.has(host);
  } catch {
    return false;
  }
}

const REMEDIATION_URL =
  'Pin to a published, named version on the official registry. URL or git installs bypass every advisory and lock-file integrity check.';
const REMEDIATION_REGISTRY =
  'Verify which registry this is, who controls it, and that you intended to pull from it. Custom indexes are a primary supply-chain attack vector.';
const REMEDIATION_TYPOSQUAT =
  'Confirm the package name letter-by-letter. Attackers publish packages whose names differ by one character from popular ones.';

export const ecosystemRule: Rule = {
  id: 'ecosystem',
  category: 'ecosystem',
  appliesTo: ['command'],
  run(input) {
    const findings: Finding[] = [];

    const hit = input.match(INSTALL_AND_TARGET);
    const target = hit?.[2];

    if (target && hit && hit.index != null) {
      const start = hit.index + hit[0].indexOf(target);
      const span: [number, number] = [start, start + target.length];

      // 1. URL / git+ install — bypasses lockfile and registry verification.
      if (/^(?:https?:\/\/|git\+https?:\/\/|git@)/i.test(target)) {
        findings.push({
          ruleId: 'ecosystem.url_install',
          category: 'ecosystem',
          severity: 'block',
          title: 'Package install from a URL or git ref',
          message:
            'This pulls and installs code directly from a URL or git repository. There is no advisory check, no integrity check, and no published-version trail.',
          evidence: target,
          span,
          remediation: REMEDIATION_URL,
        });
      } else {
        // 2. Typosquat — only check when target looks like a package name.
        const cleanName = target.replace(/[<>=!~^@].*$/, '').toLowerCase();
        const canonical = TYPOSQUATS.get(cleanName);
        if (canonical && canonical !== cleanName) {
          findings.push({
            ruleId: 'ecosystem.typosquat',
            category: 'ecosystem',
            severity: 'warn',
            title: `Possible typosquat — did you mean "${canonical}"?`,
            message: `"${cleanName}" is a known typosquat or confused-name of "${canonical}". Installing it ships attacker code under the appearance of the real package.`,
            evidence: target,
            span,
            remediation: REMEDIATION_TYPOSQUAT,
          });
        }
      }
    }

    // 3. Custom registry / index URL — only when an installer is on the line,
    // so READMEs/notes that merely *mention* `--registry=…` don't fire.
    const reg = hit ? input.match(CUSTOM_REGISTRY) : null;
    if (reg && reg.index != null && !isDefaultRegistry(reg[1])) {
      findings.push({
        ruleId: 'ecosystem.custom_registry',
        category: 'ecosystem',
        severity: 'warn',
        title: 'Install routed through a custom registry',
        message:
          'This command tells the package manager to fetch from a non-default registry. If the operator of that registry is not who you think it is, every package fetched is theirs to substitute.',
        evidence: reg[0],
        span: [reg.index, reg.index + reg[0].length],
        remediation: REMEDIATION_REGISTRY,
      });
    }

    return findings;
  },
};

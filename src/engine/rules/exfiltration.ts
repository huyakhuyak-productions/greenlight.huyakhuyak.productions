import type { Finding, Rule } from '../types';

// Sensitive filesystem paths whose contents leaving the machine = credential leak.
// We match these as substrings inside the @-argument so curl quoting doesn't matter.
const SENSITIVE_PATH = new RegExp(
  [
    '/etc/(?:passwd|shadow|sudoers)',
    '~?/?\\.ssh/(?:id_[a-z0-9]+|authorized_keys|known_hosts)',
    '~?/?\\.aws/(?:credentials|config)',
    '~?/?\\.netrc',
    '~?/?\\.npmrc',
    '~?/?\\.pypirc',
    '~?/?\\.docker/config\\.json',
    '~?/?\\.kube/config',
    '~?/?\\.gnupg/',
    '~?/?\\.config/gh/',
    '~?/?\\.git-credentials',
  ].join('|'),
  'i',
);

// curl -d @<path> | --data @<path> | --data-binary @<path> | --data-raw @<path>
//   -F field=@<path>  (multipart upload)
// We capture the @-argument so we can check whether the path is sensitive.
const CURL_AT_FILE = /\bcurl\b[^\n]*?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)\s+(?:"([^"]+)"|'([^']+)'|(\S+))/gi;

// curl -T <path> https://... — file upload (PUT-style).
const CURL_UPLOAD = /\bcurl\b[^\n]*?\s(?:-T|--upload-file)\s+(?:"([^"]+)"|'([^']+)'|(\S+))/i;

// POST body referencing an obviously-secret env var.
// SECRET, TOKEN, PASSWORD/PASS/PWD, KEY (with API/AWS/GH/GITHUB prefix), AUTH.
const SECRET_ENV_VAR =
  /\$\{?(?:[A-Z][A-Z0-9_]*?_)?(?:SECRET(?:_[A-Z0-9_]+)?|TOKEN(?:_[A-Z0-9_]+)?|API_KEY|ACCESS_KEY|PRIVATE_KEY|PASSWORD|PASSWD|AUTH_HEADER|AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET[A-Z_]*|AWS_ACCESS[A-Z_]*)\b\}?/;

// Matches `curl`/`wget`/`http`/`httpie` … `-d|--data*|--post-data` and
// captures the body argument (quoted or bare) so we can scope the env-var
// search to the body alone — not headers, not URLs.
const POST_BODY_ARG =
  /\b(?:curl|wget|http|httpie)\b[^\n]*?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|--post-data)[ =]\s*(?:"([^"]*)"|'([^']*)'|(\S+))/gi;

const REMEDIATION_FILE =
  'Never POST credential or secret files to URLs. If you need to share a file, copy specific non-sensitive fields by hand.';
const REMEDIATION_ENV =
  'Do not interpolate secret-looking environment variables into outbound POST bodies. Use a configured client (env-aware SDK, secrets manager) instead.';

export const exfiltrationRule: Rule = {
  id: 'exfiltration',
  category: 'exfiltration',
  appliesTo: ['command'],
  run(input) {
    const findings: Finding[] = [];

    // 1. curl -d @sensitive-file / -F file=@sensitive-file
    for (const m of input.matchAll(CURL_AT_FILE)) {
      const arg = m[1] ?? m[2] ?? m[3] ?? '';
      // Only @-prefixed args read file contents. -d "literal" is a literal payload.
      const at = arg.indexOf('@');
      if (at < 0) continue;
      const path = arg.slice(at + 1).replace(/^[A-Za-z][A-Za-z0-9_-]*=/, '');
      if (!SENSITIVE_PATH.test(path)) continue;
      const start = m.index ?? 0;
      findings.push({
        ruleId: 'exfiltration.curl_post_credential_file',
        category: 'exfiltration',
        severity: 'block',
        title: 'Credential or secret file being POSTed',
        message:
          'A curl flag is reading the contents of a file that holds credentials, keys, or other secrets and sending them to a remote URL.',
        evidence: m[0],
        span: [start, start + m[0].length],
        remediation: REMEDIATION_FILE,
      });
      break; // one finding for this category is enough for the verdict
    }

    // 2. curl -T <sensitive-file>
    {
      const m = input.match(CURL_UPLOAD);
      const arg = m?.[1] ?? m?.[2] ?? m?.[3];
      if (m && arg && SENSITIVE_PATH.test(arg)) {
        const start = m.index ?? 0;
        findings.push({
          ruleId: 'exfiltration.curl_upload_credential_file',
          category: 'exfiltration',
          severity: 'block',
          title: 'Sensitive file being uploaded',
          message:
            'curl is uploading a file from a path that typically holds credentials or keys. The remote server will receive the full contents.',
          evidence: m[0],
          span: [start, start + m[0].length],
          remediation: REMEDIATION_FILE,
        });
      }
    }

    // 3. POST that interpolates a secret-named env var — but only when the
    //    secret-shaped variable appears inside the actual body argument, not
    //    in an Authorization header or query string.
    for (const m of input.matchAll(POST_BODY_ARG)) {
      const body = m[1] ?? m[2] ?? m[3] ?? '';
      const envInBody = body.match(SECRET_ENV_VAR);
      if (!envInBody || envInBody.index == null) continue;
      const bodyOffset = (m.index ?? 0) + m[0].indexOf(body);
      const start = bodyOffset + envInBody.index;
      findings.push({
        ruleId: 'exfiltration.env_secret_in_post',
        category: 'exfiltration',
        severity: 'warn',
        title: 'Secret-looking env var in outbound POST body',
        message:
          'The POST body interpolates a variable whose name suggests it holds a secret (API key, token, AWS credential). Even short-lived secrets should not leave the machine in URL or body parameters.',
        evidence: envInBody[0],
        span: [start, start + envInBody[0].length],
        remediation: REMEDIATION_ENV,
      });
      break;
    }

    return findings;
  },
};

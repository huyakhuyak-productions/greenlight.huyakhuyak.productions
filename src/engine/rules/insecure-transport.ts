import type { Finding, Rule } from '../types';

const CURL_TLS_OFF = /\bcurl\b[^\n]*\s(?:-k\b|--insecure\b)/i;
const WGET_TLS_OFF = /\bwget\b[^\n]*\s--no-check-certificate\b/i;
const NODE_TLS_OFF = /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/;
const PYTHONHTTPSVERIFY_OFF = /\bPYTHONHTTPSVERIFY\s*=\s*['"]?0['"]?/;

const HTTP_PIPE_SHELL =
  /\b(?:curl|wget|fetch)\b[^\n]*\bhttp:\/\/[^\s|]+[^\n|]*(?:\|\s*[^|\n]*?)*\|\s*(?:bash|sh|zsh|fish|ksh|dash|ash|python3?|ruby|perl|node|deno|bun|php|powershell|pwsh)\b/i;

const PLAIN_HTTP_FETCH = /\b(?:curl|wget|fetch)\b[^\n]*\shttp:\/\//i;

function findFirstSpan(input: string, re: RegExp): { evidence: string; span: [number, number] } | null {
  const m = input.match(re);
  if (!m || m.index == null) return null;
  return { evidence: m[0], span: [m.index, m.index + m[0].length] };
}

export const insecureTransportRule: Rule = {
  id: 'insecure_transport',
  category: 'insecure-transport',
  appliesTo: ['command'],
  run(input) {
    const findings: Finding[] = [];

    const tlsOff =
      findFirstSpan(input, CURL_TLS_OFF) ?? findFirstSpan(input, WGET_TLS_OFF);
    if (tlsOff) {
      findings.push({
        ruleId: 'insecure_transport.tls_disabled',
        category: 'insecure-transport',
        severity: 'warn',
        title: 'TLS verification disabled',
        message:
          'This command tells the fetcher to ignore TLS certificate errors. A man-in-the-middle attacker can serve any payload they want and you will not notice.',
        evidence: tlsOff.evidence,
        span: tlsOff.span,
        remediation: 'Drop the -k / --insecure / --no-check-certificate flag and fix the certificate trust issue properly.',
      });
    }

    const nodeOff = findFirstSpan(input, NODE_TLS_OFF) ?? findFirstSpan(input, PYTHONHTTPSVERIFY_OFF);
    if (nodeOff) {
      findings.push({
        ruleId: 'insecure_transport.node_tls_reject',
        category: 'insecure-transport',
        severity: 'warn',
        title: 'TLS verification turned off via env var',
        message:
          'Setting NODE_TLS_REJECT_UNAUTHORIZED=0 (or PYTHONHTTPSVERIFY=0) makes every outbound HTTPS request accept any certificate for this process — including obviously forged ones.',
        evidence: nodeOff.evidence,
        span: nodeOff.span,
        remediation: 'Configure CA certificates correctly instead. If you only need to bypass TLS once, use a proxy with proper trust.',
      });
    }

    const httpPipe = findFirstSpan(input, HTTP_PIPE_SHELL);
    if (httpPipe) {
      findings.push({
        ruleId: 'insecure_transport.http_pipe_shell',
        category: 'insecure-transport',
        severity: 'block',
        title: 'Plain HTTP piped to a shell',
        message:
          'Code is being downloaded over plaintext HTTP and immediately piped into a shell. Anyone on the network path can substitute the payload before it reaches you.',
        evidence: httpPipe.evidence,
        span: httpPipe.span,
        remediation: 'Use HTTPS, and after that, download-then-inspect-then-run rather than pipe directly.',
      });
    } else {
      const plain = findFirstSpan(input, PLAIN_HTTP_FETCH);
      if (plain) {
        findings.push({
          ruleId: 'insecure_transport.plain_http',
          category: 'insecure-transport',
          severity: 'warn',
          title: 'Plain HTTP fetch',
          message:
            'This command fetches over HTTP, not HTTPS. Anyone on the network path can read or modify what comes back.',
          evidence: plain.evidence,
          span: plain.span,
          remediation: 'Use the https:// equivalent of this URL when one exists.',
        });
      }
    }

    return findings;
  },
};

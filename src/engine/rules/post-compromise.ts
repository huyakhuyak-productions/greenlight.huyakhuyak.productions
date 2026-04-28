import type { Finding, Rule } from '../types';

// Container escape: privileged + host-mount + namespace-share flags on
// `docker run`. Each one alone is enough to break out of the container.
const DOCKER_PRIVILEGED = /\bdocker\s+run\b[^\n]*\s--privileged\b/;
const DOCKER_CAP_ADD_ALL = /\bdocker\s+run\b[^\n]*\s--cap-add(?:=|\s+)(?:ALL|all)\b/;
// `-v /:/<anything>` or `--volume /:/<anything>` mounts the host root into
// the container; from there, chroot/edit-anything-on-host is trivial.
const DOCKER_HOST_ROOT_MOUNT =
  /\bdocker\s+run\b[^\n]*\s(?:-v\s+|--volume(?:=|\s+))\/:\/[^\s:]+/;
const DOCKER_HOST_NS = /\bdocker\s+run\b[^\n]*\s--(?:pid|ipc|net|network)(?:=|\s+)host\b/;

// Process-memory dumping: extract secrets from the running address space of
// another process. Almost never used outside debugging or post-exploitation.
const PROC_MEM_READ = /\b(?:cat|dd|cp|head|tail|xxd|hexdump|strings)\s+[^\n]*\/proc\/\d+\/(?:mem|maps|environ)\b/;
const PROC_MEM_TOOLS = /\b(?:gcore|procdump|procmemdump|mimikatz|lsass\.dmp)\b/i;

// Direct credential-file reads: the keys an attacker grabs first.
const CRED_FILE_READ =
  /\b(?:cat|head|tail|less|more|bat|xxd|cp|tar)\s+[^\n]*(?:~\/\.aws\/credentials|~\/\.aws\/config|~\/\.ssh\/id_[a-z0-9]+|~\/\.netrc|~\/\.docker\/config\.json|~\/\.kube\/config|\.pgpass|\.config\/gcloud\/[^\s]+\.json)\b/;

// /etc/shadow / getent shadow — root-only file with hashed passwords.
const SHADOW_READ = /\b(?:cat|head|tail|less|more|bat|xxd|cp)\s+[^\n]*\/etc\/shadow\b/;
const GETENT_SHADOW = /\bgetent\s+shadow\b/;

// Filesystem credential sweeps: find / grep across the entire filesystem
// looking for keys, passwords, tokens. Wide-net pattern is the giveaway.
const FIND_KEY_SWEEP =
  /\bfind\s+(?:\/|~|\$HOME)\s+[^\n]*-(?:i?name|iname|name)\s+['"]?(?:\*\.pem|id_[a-z0-9_*]+|\*\.key|\*\.p12|\*credential[s]?\*|\*token[s]?\*|\.env)['"]?/i;
const GREP_SECRET_SWEEP =
  /\bgrep\s+[^\n]*-r[a-zA-Z]*\s+[^\n]*['"](?:password|api[_\s-]?key|secret[_\s-]?key|token|aws_access_key|bearer)['"]?/i;

const REMEDIATION_CONTAINER_ESCAPE =
  'These flags on `docker run` give the container effectively the same authority as the host. A pasted command should never need to go through them; if you do, isolate the workload in a real VM, not a container.';

const REMEDIATION_PROCESS_MEM =
  'Reading process memory or dumping another process is how attackers extract in-memory secrets (session tokens, decryption keys, password caches). Outside a debugger session you never need this.';

const REMEDIATION_CRED_READ =
  'A pasted snippet that reads a credential file is staging exfiltration. Even if the next step is innocuous, the credential bytes are now in shell history and any tee/pipe target.';

const REMEDIATION_SWEEP =
  'Wide-net filesystem searches for keys, tokens, or passwords are reconnaissance — they only make sense if the next step is to send the results somewhere. If you genuinely lost a credential, search a known directory, not the whole tree.';

export const postCompromiseRule: Rule = {
  id: 'post-compromise',
  category: 'post-compromise',
  appliesTo: ['command', 'config'],
  run(input) {
    const findings: Finding[] = [];

    const containerEscapeChecks: Array<{ re: RegExp; title: string }> = [
      { re: DOCKER_PRIVILEGED, title: 'Container started with --privileged' },
      { re: DOCKER_CAP_ADD_ALL, title: 'Container granted every Linux capability' },
      { re: DOCKER_HOST_ROOT_MOUNT, title: 'Host root mounted into container' },
      { re: DOCKER_HOST_NS, title: 'Container shares a host namespace' },
    ];
    for (const { re, title } of containerEscapeChecks) {
      const m = input.match(re);
      if (m && m.index != null) {
        findings.push({
          ruleId: 'post_compromise.container_escape',
          category: 'post-compromise',
          severity: 'block',
          title,
          message:
            'This `docker run` flag dissolves the isolation boundary between container and host. Anything inside the container can read, write, or kill processes on the host.',
          evidence: m[0],
          span: [m.index, m.index + m[0].length],
          remediation: REMEDIATION_CONTAINER_ESCAPE,
        });
        break;
      }
    }

    const memMatch = input.match(PROC_MEM_READ) ?? input.match(PROC_MEM_TOOLS);
    if (memMatch && memMatch.index != null) {
      findings.push({
        ruleId: 'post_compromise.process_memory_dump',
        category: 'post-compromise',
        severity: 'block',
        title: 'Process-memory extraction',
        message:
          'The command is reading or dumping another process\'s address space. This is the textbook way to extract secrets that were decrypted into memory but never written to disk.',
        evidence: memMatch[0],
        span: [memMatch.index, memMatch.index + memMatch[0].length],
        remediation: REMEDIATION_PROCESS_MEM,
      });
    }

    const credMatch = input.match(CRED_FILE_READ);
    if (credMatch && credMatch.index != null) {
      findings.push({
        ruleId: 'post_compromise.credential_file_read',
        category: 'post-compromise',
        severity: 'block',
        title: 'Credential file read',
        message:
          'The command reads a file that holds long-lived credentials (AWS, SSH, Kubernetes, gcloud, .netrc). In a pasted snippet this almost always feeds an exfiltration step on the same line or shortly after.',
        evidence: credMatch[0],
        span: [credMatch.index, credMatch.index + credMatch[0].length],
        remediation: REMEDIATION_CRED_READ,
      });
    }

    const shadowMatch = input.match(SHADOW_READ) ?? input.match(GETENT_SHADOW);
    if (shadowMatch && shadowMatch.index != null) {
      findings.push({
        ruleId: 'post_compromise.shadow_read',
        category: 'post-compromise',
        severity: 'block',
        title: '/etc/shadow access',
        message:
          'The command is reading hashed passwords from /etc/shadow. This is a privilege-escalation step, not a configuration step — the contents are useless to anything except an offline cracker.',
        evidence: shadowMatch[0],
        span: [shadowMatch.index, shadowMatch.index + shadowMatch[0].length],
        remediation: REMEDIATION_CRED_READ,
      });
    }

    const sweepMatch = input.match(FIND_KEY_SWEEP) ?? input.match(GREP_SECRET_SWEEP);
    if (sweepMatch && sweepMatch.index != null) {
      findings.push({
        ruleId: 'post_compromise.credential_sweep',
        category: 'post-compromise',
        severity: 'warn',
        title: 'Filesystem credential sweep',
        message:
          'The command walks the filesystem looking for keys, passwords, or tokens. Outside an inventory/audit script, this shape only makes sense as reconnaissance for a follow-up exfiltration step.',
        evidence: sweepMatch[0],
        span: [sweepMatch.index, sweepMatch.index + sweepMatch[0].length],
        remediation: REMEDIATION_SWEEP,
      });
    }

    return findings;
  },
};

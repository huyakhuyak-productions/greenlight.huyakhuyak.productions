import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';

describe('command-safety', () => {
  describe('malicious / destructive', () => {
    it('flags rm -rf /', () => {
      const v = validate('rm -rf /');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('flags rm -rf /*', () => {
      const v = validate('sudo rm -rf /*');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('flags rm -rf $HOME', () => {
      const v = validate('rm -rf "$HOME"');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('flags rm -rf ~/', () => {
      const v = validate('rm -rf ~/');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('blocks overwriting ~/.bashrc with single > (truncation)', () => {
      const v = validate('echo "alias hax=foo" > ~/.bashrc');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('blocks overwriting ~/.ssh/authorized_keys', () => {
      const v = validate('echo "ssh-rsa AAA..." > ~/.ssh/authorized_keys');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('blocks overwrite of /etc/hosts', () => {
      const v = validate('echo "127.0.0.1 evil.example.com" > /etc/hosts');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('blocks append to /etc/sudoers', () => {
      const v = validate('echo "alice ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('blocks dd to xvda (AWS EC2 root device)', () => {
      const v = validate('dd if=/dev/zero of=/dev/xvda bs=4M');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('blocks the cloud metadata endpoint (escalated from warn)', () => {
      const v = validate('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('flags fork bomb', () => {
      const v = validate(':(){ :|:& };:');
      expect(v.severity).toBe('block');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('flags chmod 777 on / or /etc', () => {
      const v = validate('chmod -R 777 /');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('flags dd of=/dev/sda', () => {
      const v = validate('dd if=/dev/zero of=/dev/sda bs=4M');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });

    it('warns (does not block) on legitimate-shaped >> ~/.zshrc append', () => {
      const v = validate('echo "export NVM_DIR=$HOME/.nvm" >> ~/.zshrc');
      expect(v.severity).toBe('warn');
      expect(v.findings.some((f) => f.category === 'command-safety')).toBe(true);
    });
  });

  describe('benign', () => {
    it('does not flag rm -rf ./build (relative project path)', () => {
      const v = validate('rm -rf ./build');
      expect(v.severity).toBe('allow');
    });

    it('does not flag rm of a single named file', () => {
      const v = validate('rm package-lock.json');
      expect(v.severity).toBe('allow');
    });

    it('does not flag chmod 644 on a file', () => {
      const v = validate('chmod 644 ./script.sh');
      expect(v.severity).toBe('allow');
    });

    it('does not flag normal redirection to a project file', () => {
      const v = validate('echo "hello" > out.txt');
      expect(v.severity).toBe('allow');
    });
  });
});

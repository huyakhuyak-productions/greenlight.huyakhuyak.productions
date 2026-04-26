import { describe, it, expect } from 'vitest';
import { validate } from '../../src/engine';
import { runRules } from '../../src/engine/runner';
import type { Rule } from '../../src/engine/types';

describe('engine entry point', () => {
  it('returns allow verdict for empty input', () => {
    const v = validate('');
    expect(v.severity).toBe('allow');
    expect(v.findings).toEqual([]);
  });

  it('returns allow verdict for benign command', () => {
    const v = validate('ls -la');
    expect(v.severity).toBe('allow');
    expect(v.kind).toBe('command');
  });

  it('forces kind when provided', () => {
    const v = validate('ls', 'config');
    expect(v.kind).toBe('config');
  });
});

describe('runner', () => {
  const blockRule: Rule = {
    id: 'test.always-block',
    category: 'pipe-to-shell',
    appliesTo: 'any',
    run: (input) => [
      {
        ruleId: 'test.always-block',
        category: 'pipe-to-shell',
        severity: 'block',
        title: 'always-block',
        message: 'this rule always blocks',
        evidence: input.slice(0, 10),
      },
    ],
  };

  const warnRule: Rule = {
    id: 'test.always-warn',
    category: 'ecosystem',
    appliesTo: 'any',
    run: () => [
      {
        ruleId: 'test.always-warn',
        category: 'ecosystem',
        severity: 'warn',
        title: 'always-warn',
        message: 'this rule always warns',
      },
    ],
  };

  const buggyRule: Rule = {
    id: 'test.buggy',
    category: 'environment',
    appliesTo: 'any',
    run: () => {
      throw new Error('rule blew up');
    },
  };

  it('returns allow when no rules match', () => {
    const v = runRules('ls -la', 'command', []);
    expect(v.severity).toBe('allow');
    expect(v.findings).toHaveLength(0);
  });

  it('escalates to block when any rule blocks', () => {
    const v = runRules('anything', 'command', [warnRule, blockRule]);
    expect(v.severity).toBe('block');
    expect(v.findings).toHaveLength(2);
  });

  it('returns warn when only warn rules fire', () => {
    const v = runRules('anything', 'command', [warnRule]);
    expect(v.severity).toBe('warn');
  });

  it('skips rules that throw without breaking the verdict', () => {
    const v = runRules('anything', 'command', [buggyRule, warnRule]);
    expect(v.severity).toBe('warn');
    expect(v.findings).toHaveLength(1);
  });

  it('only runs rules whose appliesTo matches the input kind', () => {
    const urlOnly: Rule = { ...blockRule, appliesTo: ['url'] };
    const v = runRules('anything', 'command', [urlOnly]);
    expect(v.severity).toBe('allow');
  });
});

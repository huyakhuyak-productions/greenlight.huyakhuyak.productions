import { classify } from './classify';
import { runRules } from './runner';
import type { Kind, Rule, Verdict } from './types';
import { ALL_RULES } from './rules';

export type { Severity, Kind, Category, Finding, Verdict, Rule } from './types';
export { classify } from './classify';

export function validate(input: string, forcedKind?: Kind, rules: ReadonlyArray<Rule> = ALL_RULES): Verdict {
  const kind = forcedKind ?? classify(input);
  return runRules(input, kind, rules);
}

import type { Rule } from '../types';
import { pipeToShellRule } from './pipe-to-shell';
import { base64ExecRule } from './base64-exec';
import { terminalInjectionRule } from './terminal-injection';
import { insecureTransportRule } from './insecure-transport';
import { homographRule } from './homograph';
import { exfiltrationRule } from './exfiltration';
import { credentialsRule } from './credentials';
import { commandSafetyRule } from './command-safety';
import { steganographyRule } from './steganography';
import { environmentRule } from './environment';
import { ecosystemRule } from './ecosystem';
import { configInjectionRule } from './config-injection';

export const ALL_RULES: ReadonlyArray<Rule> = [
  pipeToShellRule,
  base64ExecRule,
  terminalInjectionRule,
  insecureTransportRule,
  homographRule,
  exfiltrationRule,
  credentialsRule,
  commandSafetyRule,
  steganographyRule,
  environmentRule,
  ecosystemRule,
  configInjectionRule,
];

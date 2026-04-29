import type { Kind } from './types';

const URL_RE = /^[a-z][a-z0-9+\-.]*:\/\/\S+$/i;

const CONFIG_HINTS = [
  /"\s*mcpServers\s*"/i,
  /"\s*command\s*"\s*:/i,
  /^\s*\[[a-z0-9_.-]+\]\s*$/im, // TOML section header
  /^\s*[a-z_][a-z0-9_]*:\s*$/im, // YAML key with no value
  /^\s*-\s+\w/m, // YAML list item
  /\bCLAUDE\.md\b/,
  /\.cursorrules\b/,
  /\.windsurfrules\b/,
];

export function classify(input: string): Kind {
  const trimmed = input.trim();

  if (trimmed === '') return 'command';

  if (URL_RE.test(trimmed)) return 'url';

  const lineCount = trimmed.split(/\r?\n/).length;
  const looksLikeJsonObject = trimmed.startsWith('{') && trimmed.endsWith('}');
  const looksLikeJsonArray = trimmed.startsWith('[') && trimmed.endsWith(']');
  const hasConfigHint = CONFIG_HINTS.some((re) => re.test(trimmed));

  // Multi-line + structural hints is the easy case.
  if (lineCount > 1 && (looksLikeJsonObject || looksLikeJsonArray || hasConfigHint)) {
    return 'config';
  }

  // Single-line JSON that parses successfully and contains an MCP-style
  // `command`/`args` shape is just a minified config — `claude config` and
  // most JSON editors emit it on one line. Without this branch the
  // config-injection rule never fires on minified MCP configs.
  if (lineCount === 1 && (looksLikeJsonObject || looksLikeJsonArray) && hasConfigHint) {
    try {
      JSON.parse(trimmed);
      return 'config';
    } catch {
      // Not actually JSON — fall through to `command`.
    }
  }

  return 'command';
}

import { describe, it, expect } from 'vitest';
import { classify } from '../../src/engine/classify';

describe('classify', () => {
  it('classifies a bare https URL as url', () => {
    expect(classify('https://example.com/install.sh')).toBe('url');
  });

  it('classifies a bare http URL as url', () => {
    expect(classify('http://example.com')).toBe('url');
  });

  it('classifies a URL with surrounding whitespace as url', () => {
    expect(classify('   https://example.com   ')).toBe('url');
  });

  it('classifies a single-line shell command as command', () => {
    expect(classify('ls -la')).toBe('command');
  });

  it('classifies a curl-pipe-bash one-liner as command', () => {
    expect(classify('curl -fsSL https://example.com/install.sh | bash')).toBe('command');
  });

  it('classifies an empty string as command (default)', () => {
    expect(classify('')).toBe('command');
  });

  it('classifies a JSON MCP config as config', () => {
    const input = `{
  "mcpServers": {
    "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"] }
  }
}`;
    expect(classify(input)).toBe('config');
  });

  it('classifies a YAML rules block as config', () => {
    const input = `rules:
  - name: thing
    args: ["--flag"]
`;
    expect(classify(input)).toBe('config');
  });

  it('classifies a multi-line shell script as command (heredoc-ish)', () => {
    const input = `set -e
echo hello
echo world`;
    expect(classify(input)).toBe('command');
  });

  it('does not misclassify a URL with a query string as command', () => {
    expect(classify('https://example.com/path?q=1&r=2')).toBe('url');
  });

  it('does not classify a URL with a space inside it as url', () => {
    // A space means it's not a single URL — likely a command
    expect(classify('curl https://example.com')).toBe('command');
  });

  it('classifies a TOML-shaped config as config', () => {
    const input = `[server]
command = "node"
args = ["script.js"]`;
    expect(classify(input)).toBe('config');
  });
});

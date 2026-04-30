import { describe, it, expect } from 'vitest';
import { extractFirstFetchedUrl, extractUrls, hostOf } from '../../src/lib/url';

describe('extractFirstFetchedUrl', () => {
  describe('pulls the URL out of pipe-to-shell evidence', () => {
    it('matches curl <url> | bash', () => {
      expect(extractFirstFetchedUrl('curl -fsSL https://get.example.com/install.sh | bash')).toBe(
        'https://get.example.com/install.sh',
      );
    });

    it('matches wget <url> | sh', () => {
      expect(extractFirstFetchedUrl('wget -qO- https://example.com/x | sh')).toBe(
        'https://example.com/x',
      );
    });

    it('matches process substitution: bash <(curl <url>)', () => {
      expect(
        extractFirstFetchedUrl('bash <(curl -fsSL https://example.com/install.sh)'),
      ).toBe('https://example.com/install.sh');
    });

    it('matches eval $(curl <url>)', () => {
      expect(extractFirstFetchedUrl('eval "$(curl -s https://example.com/x)"')).toBe(
        'https://example.com/x',
      );
    });

    it('matches inline interpreter: sh -c "$(curl <url>)"', () => {
      expect(
        extractFirstFetchedUrl(
          'sh -c "$(curl -fsSL https://raw.githubusercontent.com/foo/bar/install.sh)"',
        ),
      ).toBe('https://raw.githubusercontent.com/foo/bar/install.sh');
    });

    it('matches herestring: bash <<< "$(curl <url>)"', () => {
      expect(extractFirstFetchedUrl('bash <<< "$(curl -s https://example.com/x.sh)"')).toBe(
        'https://example.com/x.sh',
      );
    });

    it('matches PowerShell iex (irm <url>)', () => {
      expect(extractFirstFetchedUrl('iex (irm https://example.com/x.ps1)')).toBe(
        'https://example.com/x.ps1',
      );
    });

    it('matches save-then-execute', () => {
      expect(
        extractFirstFetchedUrl(
          'curl -o /tmp/install.sh https://example.com/install.sh && bash /tmp/install.sh',
        ),
      ).toBe('https://example.com/install.sh');
    });

    it('returns the first URL when evidence contains multiple', () => {
      expect(
        extractFirstFetchedUrl(
          'curl https://first.example.com/a | tee https://second.example.com/b',
        ),
      ).toBe('https://first.example.com/a');
    });

    it('strips a trailing semicolon picked up from a compound command', () => {
      expect(extractFirstFetchedUrl('curl https://example.com/x.sh;')).toBe(
        'https://example.com/x.sh',
      );
    });

    it('strips a trailing comma', () => {
      expect(extractFirstFetchedUrl('see https://example.com/x.sh, then run it')).toBe(
        'https://example.com/x.sh',
      );
    });

    it('handles plain http:// (not just https://)', () => {
      expect(extractFirstFetchedUrl('curl http://example.com/x | sh')).toBe(
        'http://example.com/x',
      );
    });
  });

  describe('rejects non-fetchable inputs', () => {
    it('returns null for evidence with no URL', () => {
      expect(extractFirstFetchedUrl('rm -rf /')).toBeNull();
    });

    it('returns null for an empty string', () => {
      expect(extractFirstFetchedUrl('')).toBeNull();
    });

    it('returns null for file:// URLs (not fetchable from a browser)', () => {
      expect(extractFirstFetchedUrl('cat file:///etc/passwd')).toBeNull();
    });

    it('returns null for ftp:// URLs', () => {
      expect(extractFirstFetchedUrl('curl ftp://example.com/x.sh')).toBeNull();
    });

    it('skips non-http schemes but picks up an https one later in the string', () => {
      expect(
        extractFirstFetchedUrl('open file:///tmp/x then curl https://example.com/y | bash'),
      ).toBe('https://example.com/y');
    });
  });
});

describe('hostOf', () => {
  it('returns the host of an https URL', () => {
    expect(hostOf('https://example.com/path')?.host).toBe('example.com');
  });

  it('returns null for a non-URL', () => {
    expect(hostOf('not a url')).toBeNull();
  });

  it('honors the 32-char scheme bound (defends against ReDoS)', () => {
    // The bound allows the first char plus up to 32 more, i.e. 33 total.
    // A 34-char scheme is past the cap and should not match.
    const longScheme = 'a'.repeat(34) + '://example.com/x';
    expect(hostOf(longScheme)).toBeNull();
  });
});

describe('extractUrls', () => {
  it('returns multiple URLs in document order', () => {
    const out = extractUrls('see https://a.example.com/x and https://b.example.com/y');
    expect(out.map((u) => u.host)).toEqual(['a.example.com', 'b.example.com']);
  });

  it('reports correct host span offsets', () => {
    const input = 'curl https://example.com/x';
    const [u] = extractUrls(input);
    expect(input.slice(u.hostStart, u.hostEnd)).toBe('example.com');
  });
});

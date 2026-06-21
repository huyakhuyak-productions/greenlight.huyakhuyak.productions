import { afterEach, describe, expect, it, vi } from 'vitest';
import { initAnalytics } from '../src/analytics';

const SRC = 'https://umami.example.test/script.js';
const WEBSITE_ID = '00000000-0000-0000-0000-000000000000';

function umamiScripts(doc: Document): HTMLScriptElement[] {
  return Array.from(doc.head.querySelectorAll('script[data-website-id]'));
}

describe('initAnalytics', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    document.head.querySelectorAll('script[data-website-id]').forEach((s) => s.remove());
  });

  it('injects the Umami script when both env vars are set', () => {
    vi.stubEnv('VITE_UMAMI_SRC', SRC);
    vi.stubEnv('VITE_UMAMI_WEBSITE_ID', WEBSITE_ID);

    expect(initAnalytics()).toBe(true);

    const scripts = umamiScripts(document);
    expect(scripts).toHaveLength(1);
    expect(scripts[0].src).toBe(SRC);
    expect(scripts[0].dataset.websiteId).toBe(WEBSITE_ID);
    expect(scripts[0].defer).toBe(true);
  });

  it('injects nothing when no env vars are set (opt-in default)', () => {
    vi.stubEnv('VITE_UMAMI_SRC', '');
    vi.stubEnv('VITE_UMAMI_WEBSITE_ID', '');

    expect(initAnalytics()).toBe(false);
    expect(umamiScripts(document)).toHaveLength(0);
  });

  it('stays off when only the src is set', () => {
    vi.stubEnv('VITE_UMAMI_SRC', SRC);
    vi.stubEnv('VITE_UMAMI_WEBSITE_ID', '');

    expect(initAnalytics()).toBe(false);
    expect(umamiScripts(document)).toHaveLength(0);
  });

  it('stays off when only the website id is set', () => {
    vi.stubEnv('VITE_UMAMI_SRC', '');
    vi.stubEnv('VITE_UMAMI_WEBSITE_ID', WEBSITE_ID);

    expect(initAnalytics()).toBe(false);
    expect(umamiScripts(document)).toHaveLength(0);
  });
});

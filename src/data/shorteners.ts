/**
 * Known URL shortener domains. Shortened URLs hide their final destination,
 * which means a user cannot see whether they're about to fetch a script from
 * a trustworthy origin or an attacker-controlled one.
 */
export const URL_SHORTENERS: ReadonlySet<string> = new Set([
  'bit.ly',
  'bitly.com',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'is.gd',
  'ow.ly',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  's.id',
  'rb.gy',
  'tiny.cc',
  'lnkd.in',
  'youtu.be',
  't.ly',
  'shorturl.com',
  'short.io',
]);

export function isShortener(host: string): boolean {
  const h = host.toLowerCase();
  return URL_SHORTENERS.has(h) || URL_SHORTENERS.has(h.replace(/^www\./, ''));
}

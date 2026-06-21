/**
 * Opt-in, self-hosted page-view analytics (Umami).
 *
 * Analytics ships OFF. The script is injected only when BOTH
 * `VITE_UMAMI_SRC` and `VITE_UMAMI_WEBSITE_ID` are provided at build time —
 * kept in an untracked `.env.local`, never committed (see `.env.example`).
 * With neither set — the default for the open-source build and local dev —
 * nothing is injected and the page makes zero analytics requests.
 *
 * Umami counts anonymous page views only. It never receives the user's paste,
 * which never leaves the tab. This lives in the UI layer, never in
 * `src/engine/` or `src/lib/`, so the engine's zero-network boundary holds.
 */
export function initAnalytics(doc: Document = document): boolean {
  const src = import.meta.env.VITE_UMAMI_SRC;
  const websiteId = import.meta.env.VITE_UMAMI_WEBSITE_ID;

  // Opt-in: both must be present, or analytics stays off.
  if (!src || !websiteId) return false;

  const script = doc.createElement('script');
  script.defer = true;
  script.src = src;
  script.dataset.websiteId = websiteId;
  doc.head.appendChild(script);
  return true;
}

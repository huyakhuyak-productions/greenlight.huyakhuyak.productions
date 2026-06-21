/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Self-hosted Umami script URL. Unset = analytics off (the default). */
  readonly VITE_UMAMI_SRC?: string;
  /** Umami website id paired with VITE_UMAMI_SRC. Both required to enable. */
  readonly VITE_UMAMI_WEBSITE_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

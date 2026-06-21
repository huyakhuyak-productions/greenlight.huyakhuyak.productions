# Greenlight — agent context

A client-side web validator for shell commands, URLs, and config snippets. The detection engine runs entirely in the browser and is allowed exactly zero network calls — that's a load-bearing invariant. The UI layer is allowed two kinds of network call: (1) an explicit per-finding *Scan this script* click that fetches a `curl | sh` URL so we can re-run the engine over the script body; (2) opt-in, env-gated anonymous page-view analytics (self-hosted Umami) that never sees the user's paste. Neither involves the engine, and the user's input never leaves the tab except via that explicit click. No remote rule updates, no implicit fetches of input.

## Architecture

```
Paste box → classify(input) → runRules(input, kind) → Verdict + Findings[]
```

- `src/engine/index.ts` — the only public entry point, `validate(input, kind?)`.
- `src/engine/classify.ts` — decides whether a paste is a `command`, `url`, or `config`. Each rule declares which kinds it `appliesTo`.
- `src/engine/runner.ts` — iterates rules, merges findings, picks worst severity (`block > warn > allow`).
- `src/engine/rules/*.ts` — one file per detection category. Each file exports a `Rule` (or several) with `{ id, category, appliesTo, run }`.
- `src/engine/types.ts` — `Severity`, `Kind`, `Finding`, `Verdict`, `Rule`. The full vocabulary; don't extend it casually.
- `src/lib/` — leaf helpers (Unicode tables, URL parsing, shell tokenisation, entropy). No rule logic here.
- `src/data/` — static lists (confusables, shorteners, typosquats, AI-config keys).
- `src/components/`, `src/hooks/`, `src/App.tsx` — the UI; thin around the engine.

The 15 categories are listed in `src/engine/types.ts` (`Category` union). Adding a 16th means a new rule file, a new entry in the union, and tests in `tests/engine/`.

## Stack & tooling

- **Bun** is the package manager and runtime. Use `bun add`, `bun run`, `bun test`. Don't hand-edit `package.json`.
- **Vite + React 19 + TypeScript + Tailwind v4** for the SPA.
- **Vitest** for unit tests. `tests/engine/<rule>.test.ts` for rule tests, plus a small corpus in `tests/corpus/`.
- **GSAP** for verdict animations.
- The build is a static SPA; `Dockerfile` builds it and serves `dist/` with `nginx:alpine`.

## Conventions

- **Severity vocabulary is fixed** at `block > warn > allow`. `block` means the user shouldn't run it; `warn` is "be careful"; `allow` means we found nothing. The verdict severity is the max across all findings.
- **Rules return `Finding[]`**, never throw. A rule that can't determine anything returns `[]`.
- **Findings carry evidence + span** (`span: [number, number]` byte offsets) so the UI can highlight the offending substring in the original input. New rules should populate these fields when at all possible.
- **Tests live next to behaviour, not next to files.** Each rule file has a paired `tests/engine/<rule>.test.ts` with at least three malicious cases and three benign cases. Detection tests + perf-regression tests go in the same file.
- **Commit shape: one user-visible behaviour per commit.** Tests for a behaviour belong in the same commit as the behaviour. Use the `gitmoji-commit` skill.

## Performance gotchas (read this before touching regex)

This engine runs on every keystroke in the browser. Every regex needs to be linear in input length, or close to it. The codebase has had four real ReDoS bugs already; the patterns to watch for are:

- **Unbounded `[^X]*` next to a fixed target.** `cat\s+[^\n]*\/etc\/shadow` is O(N²) on inputs with many `cat ` substrings. Bound the character class to stop at shell separators (`[^\n;&|]*`) so each candidate is local.
- **Unbounded `{2,}` on overlapping content.** `(?:\.\.\/){2,}` followed by alternatives over a long path triggers backtracking. Cap at `{2,8}` or similar; real threats don't need huge depth.
- **Greedy unbounded `*` followed by a literal that *also* appears inside it.** `(?:\|…)*\|<INTERPRETER>` is the classic catastrophic-backtracking shape — the engine has too many ways to distribute pipes between the inner group and the trailing `\|`. Don't write this. Tokenize first (split on the separator), then test segments. See `src/engine/rules/pipe-to-shell.ts` for the working pattern.
- **Unbounded scheme/host classes scanned with `matchAll`.** `[a-z]+:\/\/` on long alphabetic input with no `://` is O(N²). Bound the prefix (`[a-z][a-z0-9+\-.]{0,32}:\/\/`).

When in doubt, write a perf-regression test: build an adversarial input (a few thousand repeated tokens), `validate(...)`, assert the elapsed time is `< 150ms`. There are working examples in `tests/engine/post-compromise.test.ts`, `path-analysis.test.ts`, `pipe-to-shell.test.ts`, and `homograph.test.ts`.

## When fixing a rule, scan the rest of the engine for the same shape

If you find a ReDoS in one rule, the others probably have the same pattern. The four ReDoS fixes in this codebase landed within a few hours of each other for that reason. Same applies to detection bypasses — if combined-flag `-OL` slipped past one regex, similar regex elsewhere may be assuming bare flags too. Search for analogous patterns before declaring the fix done.

## Privacy is a feature, not a default

There is intentionally no error reporting, no remote rule updates, and no telemetry that ever sees the user's input. The engine performs zero network I/O — that boundary is non-negotiable and tested by the absence of `fetch(`, `XMLHttpRequest`, etc. anywhere in `src/engine/` and `src/lib/`. Analytics code never goes in those two directories; it lives in the UI layer (`src/analytics.ts`).

The UI layer has two allowed network calls, and nothing else:

1. **The per-finding *Scan this script* click.** It fetches a single user-pointed URL (the one already named in their paste), receives the body, and feeds it back into the same offline engine. No proxy, no third-party intermediary, no caching across pastes.
2. **Opt-in, env-gated page-view analytics.** `src/analytics.ts` injects a self-hosted Umami script *only* when both `VITE_UMAMI_SRC` and `VITE_UMAMI_WEBSITE_ID` are set at build time. The open-source build and local dev ship with neither set, so analytics is off and no request is made. The real values live in an untracked `.env.local` (see `.env.example`); they are never committed. Umami counts anonymous page views — it never receives the paste.

If a future change wants to call out to anything else — threat-intel feed, "suggest a rule" form, error reporting, or analytics that captures input — that's a product decision that needs an explicit user-visible toggle, not a silent network call.

## Out of scope (documented, don't build)

- Live threat-intel feeds (URLhaus, Feodo, PhishTank).
- Server-side anything (telemetry, shareable result URLs, accounts).
- Mobile-app or browser-extension wrappers (the engine is portable; the wrapper is a separate project if it ever happens).
- WASM port of the original `tirith` engine.

## Useful pointers

- `src/engine/index.ts` — the entry. Start here.
- `src/engine/types.ts` — the type vocabulary. Read this before adding a rule.
- `src/engine/rules/pipe-to-shell.ts` — the most-touched rule, and the cleanest example of "tokenize-then-test" instead of one mega-regex.
- `tests/engine/<rule>.test.ts` — every rule has a paired test file with the same name. Match the structure when adding new ones.
- The original detection taxonomy is from [tirith](https://github.com/sheeki03/tirith); when adding a category, check what tirith does for it before inventing something new.

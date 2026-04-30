# Greenlight

A web-based safety check for shell snippets you'd otherwise paste blindly into a terminal.

Paste a command, URL, or config blob into the page. If it's safe, the page goes **green**. If anything is off, the page goes **red** and tells you what.

The whole engine runs in your browser. **Your paste stays in the tab** — no telemetry, no analytics, no server. The only network call the page ever makes is when you click *Scan this script* on a `curl … | bash` finding: your browser fetches that URL directly so we can run the same engine over the script body. The engine itself never phones home; the click is always your move.

## Why

Half the install instructions on the modern internet are some flavour of `curl … | bash`. The shape of the threat (download arbitrary code from a server you don't control, then execute it without reading it) is well-documented and routinely abused — but the muscle memory of copy-paste is faster than the muscle memory of "wait, should I read this first?" Greenlight's job is to insert a friction-free safety check between *Cmd-C* on the blog and *Cmd-V* in the terminal.

There's a terminal-side tool for the same problem ([tirith](https://github.com/sheeki03/tirith)) — but it requires you to have already installed it, which doesn't help on a fresh machine, in a teammate's session, or for the people who would benefit most. Greenlight is a public web page: zero install, paste-and-check.

## What it detects

Fifteen categories, prioritised by how often the threat shape shows up in pasted snippets:

- **Pipe-to-shell** — `curl … | bash`, `wget … | sudo sh`, process substitution, `eval $(curl …)`, save-then-execute, PowerShell `iex`
- **Homograph & URL trickery** — Cyrillic/Greek lookalikes, mixed-script labels, punycode hostnames, URL shorteners
- **Base64 decode-execute** — `echo … | base64 -d | sh`, PowerShell `-EncodedCommand`
- **Terminal injection** — ANSI escapes, bidi overrides, zero-width chars, Unicode tag chars
- **Insecure transport** — `curl -k`, `--insecure`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `http://` piped to a shell
- **Data exfiltration** — `curl -d @/etc/passwd`, env-var POSTs, credential file uploads
- **Credential detection** — AWS keys, GitHub PATs, private-key headers, high-entropy strings
- **Command safety** — overwrites of dotfiles, archive extraction with traversal, `rm -rf /`, metadata-endpoint access
- **Steganography** — invisible whitespace, Mongolian Vowel Separator, Hangul Fillers
- **Config-file injection** — shell metacharacters in MCP `args`, prompt-injection keywords in rules files
- **Ecosystem threats** — typosquats, untrusted registries, URL-based package installs
- **Environment** — `LD_PRELOAD` exports, interpreter hijacking via shebangs, proxy hijacking
- **Code-file scanning** — dynamic-eval patterns, suspicious dynamic imports
- **Post-compromise** — Docker privilege-escalation flags, credential sweeps, process-memory tools
- **Path analysis** — non-ASCII paths, double-encoded `%2e%2e`, traversal patterns

## Running locally

```sh
bun install
bun run dev      # http://localhost:5173
bun run test     # the engine has 277+ unit tests
bun run build    # produces dist/
```

The repo uses [Bun](https://bun.sh) as the package manager and runtime. If you don't have it: `curl -fsSL https://bun.sh/install | bash` — and yes, the irony is not lost on us.

## Deploying

There's a `Dockerfile` in the root that builds the static bundle with Bun and serves it from `nginx:alpine`:

```sh
docker build --tag greenlight .
docker run --publish 8080:80 greenlight
```

The output is plain static files — point any host that serves a directory (Cloudflare Pages, Netlify, Vercel, S3+CloudFront, plain nginx on a VPS) at `dist/` and you're done.

## Stack

- [Bun](https://bun.sh) for the runtime and package manager
- [Vite](https://vitejs.dev) + [React 19](https://react.dev) + [TypeScript](https://www.typescriptlang.org) for the SPA
- [Tailwind CSS v4](https://tailwindcss.com) for styling
- [GSAP](https://gsap.com) for the verdict animations
- [Vitest](https://vitest.dev) for the engine's unit tests

## Credits

The detection categories and many of the rule shapes are lifted directly from [tirith](https://github.com/sheeki03/tirith) by [@sheeki03](https://github.com/sheeki03). Greenlight reimplements the rules in TypeScript so they can run in a browser tab, but the threat taxonomy is theirs — go give them a star.

## License

[MIT](./LICENSE).

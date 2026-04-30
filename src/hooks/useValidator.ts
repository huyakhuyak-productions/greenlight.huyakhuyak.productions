import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { validate, type Kind, type Verdict } from '../engine';
import {
  MAX_FETCHED_BODY_BYTES,
  type DownstreamErrorKind,
  type DownstreamScan,
} from '../lib/downstream';

export type KindOverride = 'auto' | Kind;

export interface UseValidatorReturn {
  input: string;
  setInput: (next: string) => void;
  kindOverride: KindOverride;
  setKindOverride: (next: KindOverride) => void;
  verdict: Verdict;
  isPending: boolean;
  downstreamScans: ReadonlyMap<string, DownstreamScan>;
  scanDownstream: (url: string) => void;
  pasteDownstreamBody: (url: string, body: string) => void;
}

export function useValidator(): UseValidatorReturn {
  const [input, setInput] = useState('');
  const [kindOverride, setKindOverride] = useState<KindOverride>('auto');
  const [downstreamScans, setDownstreamScans] = useState<ReadonlyMap<string, DownstreamScan>>(
    () => new Map(),
  );

  const deferredInput = useDeferredValue(input);
  const isPending = input !== deferredInput;

  const verdict = useMemo<Verdict>(
    () => validate(deferredInput, kindOverride === 'auto' ? undefined : kindOverride),
    [deferredInput, kindOverride],
  );

  // One AbortController per in-flight URL. Cleared on input change so a stale
  // upstream paste doesn't race a fresh one — abort old fetches before they
  // can write back into the (now-irrelevant) scans map.
  const inflightRef = useRef<Map<string, AbortController>>(new Map());

  useEffect(() => {
    for (const ctrl of inflightRef.current.values()) ctrl.abort();
    inflightRef.current.clear();
    setDownstreamScans(new Map());
  }, [input]);

  useEffect(() => {
    return () => {
      for (const ctrl of inflightRef.current.values()) ctrl.abort();
      inflightRef.current.clear();
    };
  }, []);

  const updateScan = useCallback(
    (url: string, patch: Partial<DownstreamScan> & Pick<DownstreamScan, 'status'>) => {
      setDownstreamScans((prev) => {
        const next = new Map(prev);
        const existing = prev.get(url);
        next.set(url, { ...(existing ?? { url }), ...patch, url });
        return next;
      });
    },
    [],
  );

  const runEngineOnBody = useCallback((body: string): Verdict => {
    return validate(body, 'command');
  }, []);

  const scanDownstream = useCallback(
    (url: string) => {
      // Read latest scan state via the setter so this callback's identity
      // doesn't depend on the scans Map. Returning `prev` unchanged is a
      // safe no-op (React bails out of the update).
      setDownstreamScans((prev) => {
        if (inflightRef.current.has(url)) return prev;
        const existing = prev.get(url);
        if (existing && existing.status !== 'error') return prev;

        const controller = new AbortController();
        inflightRef.current.set(url, controller);

        // Every write below — success, error, finally cleanup — only
        // takes effect if this controller is still the registered one
        // for `url`. A late-aborted fetch must NOT stomp a fresh scan's
        // state for the same URL, and the input-change effect that
        // cleared the scans Map must NOT have new entries written into
        // it by zombie controllers.
        const isOwner = () => inflightRef.current.get(url) === controller;

        (async () => {
          try {
            const res = await fetch(url, {
              signal: controller.signal,
              redirect: 'follow',
              credentials: 'omit',
              // The host being scanned is, by definition, one the user
              // is suspicious of. Don't leak the Greenlight page URL to
              // it via Referer.
              referrerPolicy: 'no-referrer',
            });
            if (!res.ok) {
              throw new HttpError(`The host responded with ${res.status} ${res.statusText}.`);
            }
            const body = await res.text();
            if (body.length > MAX_FETCHED_BODY_BYTES) {
              throw new TooLargeError(
                `The script is over ${formatBytes(MAX_FETCHED_BODY_BYTES)} (${formatBytes(body.length)}). Greenlight caps responses at this size to avoid wedging the engine.`,
              );
            }
            const downstreamVerdict = runEngineOnBody(body);
            if (!isOwner()) return;
            updateScan(url, {
              status: 'success',
              fetchedBody: body,
              verdict: downstreamVerdict,
              fetchedAt: Date.now(),
            });
          } catch (err) {
            if (!isOwner()) return;
            const { kind, reason } = classifyFetchError(err);
            updateScan(url, { status: 'error', errorKind: kind, errorReason: reason });
          } finally {
            if (isOwner()) {
              inflightRef.current.delete(url);
            }
          }
        })();

        const next = new Map(prev);
        next.set(url, { url, status: 'loading' });
        return next;
      });
    },
    [runEngineOnBody, updateScan],
  );

  const pasteDownstreamBody = useCallback(
    (url: string, body: string) => {
      const trimmed = body.trim();
      if (trimmed.length === 0) return;
      if (trimmed.length > MAX_FETCHED_BODY_BYTES) {
        updateScan(url, {
          status: 'error',
          errorKind: 'too-large',
          errorReason: `The pasted body is over ${formatBytes(MAX_FETCHED_BODY_BYTES)}.`,
        });
        return;
      }
      updateScan(url, {
        status: 'success',
        fetchedBody: trimmed,
        verdict: runEngineOnBody(trimmed),
        fetchedAt: Date.now(),
      });
    },
    [runEngineOnBody, updateScan],
  );

  return {
    input,
    setInput,
    kindOverride,
    setKindOverride,
    verdict,
    isPending,
    downstreamScans,
    scanDownstream,
    pasteDownstreamBody,
  };
}

class HttpError extends Error {}
class TooLargeError extends Error {}

function classifyFetchError(err: unknown): { kind: DownstreamErrorKind; reason: string } {
  if (err instanceof HttpError) {
    return { kind: 'http', reason: err.message };
  }
  if (err instanceof TooLargeError) {
    return { kind: 'too-large', reason: err.message };
  }
  // Browsers surface CORS failures as a generic TypeError with no useful
  // detail — there's no programmatic way to distinguish a CORS rejection
  // from "host is unreachable" or "DNS failed". Treat unspecified TypeErrors
  // as CORS, since that's the dominant cause for arbitrary install-script
  // hosts. The error UX surfaces the manual-paste fallback either way.
  if (err instanceof TypeError) {
    return {
      kind: 'cors',
      reason:
        "Your browser couldn't fetch this URL directly. Most install-script hosts don't set CORS headers, so this is the common case — fetch the file yourself and paste the body in.",
    };
  }
  const message = err instanceof Error ? err.message : 'Unknown error.';
  return { kind: 'network', reason: message };
}

function formatBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)} kB`;
  return `${n} B`;
}

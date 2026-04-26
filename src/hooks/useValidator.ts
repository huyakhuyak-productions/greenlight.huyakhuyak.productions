import { useDeferredValue, useMemo, useState } from 'react';
import { validate, type Kind, type Verdict } from '../engine';

export type KindOverride = 'auto' | Kind;

export interface UseValidatorReturn {
  input: string;
  setInput: (next: string) => void;
  kindOverride: KindOverride;
  setKindOverride: (next: KindOverride) => void;
  verdict: Verdict;
  isPending: boolean;
}

export function useValidator(): UseValidatorReturn {
  const [input, setInput] = useState('');
  const [kindOverride, setKindOverride] = useState<KindOverride>('auto');

  const deferredInput = useDeferredValue(input);
  const isPending = input !== deferredInput;

  const verdict = useMemo<Verdict>(
    () => validate(deferredInput, kindOverride === 'auto' ? undefined : kindOverride),
    [deferredInput, kindOverride],
  );

  return { input, setInput, kindOverride, setKindOverride, verdict, isPending };
}

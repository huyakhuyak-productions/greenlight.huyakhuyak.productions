import type { Verdict } from '../engine';

export type DownstreamScanStatus = 'loading' | 'success' | 'error';

export type DownstreamErrorKind = 'cors' | 'network' | 'http' | 'too-large';

export interface DownstreamScan {
  url: string;
  status: DownstreamScanStatus;
  fetchedBody?: string;
  verdict?: Verdict;
  errorReason?: string;
  errorKind?: DownstreamErrorKind;
  fetchedAt?: number;
}

export const MAX_FETCHED_BODY_BYTES = 1_000_000;

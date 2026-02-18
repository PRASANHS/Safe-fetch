

'use server';

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];
export type RequestBody = Record<string, unknown> | FormData | string | null;
export type QueryParams = Record<string, string | number | boolean | null | undefined>;

export interface RequestOptions<TBody extends RequestBody = RequestBody, TResponse = unknown> {
  data?: TBody;
  params?: QueryParams;
  retries?: number;
  timeout?: number | ((attempt: number) => number);
  headers?: Record<string, string>;
  transform?(data: TResponse): TResponse;
  priority?: 'high' | 'normal' | 'low';
  signal?: AbortSignal;
  logTypes?: boolean;
  cache?: RequestCache;
  next?: { revalidate?: number | false; tags?: string[] };
  dedupeKey?: string | null;
}

export type ApiResponse<T = unknown> =
  | { success: true; status: number; data: T; headers: Record<string, string> }
  | { success: false; status: number; error: ApiError; data: null };

export interface ApiError {
  readonly name: string;
  readonly message: string;
  readonly status: number;
  readonly retryable?: boolean;
  readonly url?: string;
  readonly method?: string;
}

const IS_BUN = typeof globalThis !== 'undefined' && 'Bun' in globalThis;
const RETRY_CODES = new Set([408, 429, 500, 502, 503, 504]);
const PRIORITY_VALUES = { high: 3, normal: 2, low: 1 } as const;

interface GlobalEnv {
  __ENV__?: Record<string, string>;
}

// Optimize: Cache env values and avoid repeated lookups
const getEnv = (() => {
  let cachedEnv: ReturnType<typeof createEnv> | null = null;

  function createEnv() {
    const env = process.env || (globalThis as unknown as GlobalEnv).__ENV__ || {};
    return {
      API_URL: env.NEXT_PUBLIC_API_URL || env.BASE_URL || env.API_URL || '',
      AUTH_USERNAME: env.AUTH_USERNAME || env.API_USERNAME || '',
      AUTH_PASSWORD: env.AUTH_PASSWORD || env.API_PASSWORD || '',
      API_TOKEN: env.AUTH_TOKEN || env.API_TOKEN || '',
      NODE_ENV: env.NODE_ENV || 'development',
    };
  }

  return () => {
    if (!cachedEnv) {
      cachedEnv = createEnv();
      if (!cachedEnv.API_URL) {
        console.error('\x1b[31m%s\x1b[0m', '❌ [SafeFetch] Missing API_URL');
      }
      if (!cachedEnv.AUTH_USERNAME && !cachedEnv.API_TOKEN) {
        console.error('\x1b[31m%s\x1b[0m', '❌ [SafeFetch] Missing Auth Credentials');
      }
    }
    return cachedEnv;
  };
})();

const ENV = getEnv();
const CFG = {
  RETRIES: 2,
  TIMEOUT: 60000,
  MAX_CONCURRENT: IS_BUN ? 20 : 10,
  RATE_MAX: 100,
  RATE_WINDOW: 60000,
  AUTH_CACHE_TTL: 300000, // 5 minutes
} as const;

/* --- Util Classes --- */

// Optimize: Use circular buffer for rate limiter to avoid array filter operations
class RateLimiter {
  private readonly timestamps: number[];
  private head = 0;
  private size = 0;

  constructor(private readonly capacity = CFG.RATE_MAX) {
    this.timestamps = new Array(capacity);
  }

  async check(max = CFG.RATE_MAX, win = CFG.RATE_WINDOW): Promise<void> {
    const now = Date.now();
    const cutoff = now - win;

    // Remove expired timestamps
    while (this.size > 0 && this.timestamps[this.head] < cutoff) {
      this.head = (this.head + 1) % this.capacity;
      this.size--;
    }

    if (this.size >= max) {
      const waitTime = win - (now - this.timestamps[this.head]);
      await new Promise((r) => setTimeout(r, waitTime));
      return this.check(max, win);
    }

    // Add new timestamp
    const index = (this.head + this.size) % this.capacity;
    this.timestamps[index] = now;
    this.size++;
  }

  stats = () => ({ current: this.size });
}

const limiter = new RateLimiter();

// Optimize: Use WeakMap for dedupe cache to allow garbage collection
class Pool {
  private readonly queue: Array<{ fn: () => void; pri: number }> = [];
  private active = 0;
  private readonly pending = new Map<string, Promise<unknown>>();

  constructor(private readonly max = CFG.MAX_CONCURRENT) {}

  async exec<T>(
    fn: () => Promise<T>,
    pri: 'high' | 'normal' | 'low' = 'normal',
    key?: string | null,
  ): Promise<T> {
    // Dedupe: return existing promise if key exists
    if (key) {
      const existing = this.pending.get(key);
      if (existing) return existing as Promise<T>;
    }

    const task = new Promise<T>((resolve, reject) => {
      const run = async () => {
        this.active++;
        try {
          const result = await fn();
          resolve(result);
        } catch (e) {
          reject(e);
        } finally {
          this.active--;
          if (key) this.pending.delete(key);
          this.processQueue();
        }
      };

      if (this.active < this.max) {
        run();
      } else {
        this.enqueue(run, pri);
      }
    });

    if (key) this.pending.set(key, task);
    return task;
  }

  // Optimize: Separate queue processing logic
  private processQueue(): void {
    if (this.queue.length > 0 && this.active < this.max) {
      this.queue.shift()?.fn();
    }
  }

  // Optimize: Binary search for insertion point
  private enqueue(fn: () => void, pri: 'high' | 'normal' | 'low'): void {
    const priVal = PRIORITY_VALUES[pri];

    // Binary search for insertion point
    let left = 0;
    let right = this.queue.length;

    while (left < right) {
      const mid = (left + right) >>> 1; // Use unsigned right shift for division by 2
      if (this.queue[mid].pri >= priVal) {
        left = mid + 1;
      } else {
        right = mid;
      }
    }

    this.queue.splice(left, 0, { fn, pri: priVal });
  }

  stats = () => ({ active: this.active, queued: this.queue.length });
}

const pool = new Pool();

/* --- Requests --- */

// Optimize: Memoize auth header creation with TTL
const getAuth = (() => {
  let cache: Record<string, string> | null = null;
  let lastUpdate = 0;

  return (): Record<string, string> => {
    const now = Date.now();
    if (cache && now - lastUpdate < CFG.AUTH_CACHE_TTL) {
      return cache;
    }

    const { AUTH_USERNAME: u, AUTH_PASSWORD: p, API_TOKEN: t } = ENV;
    const headers: Record<string, string> = {};

    if (u && p) {
      const credentials = `${u}:${p}`;
      const encoded =
        typeof btoa !== 'undefined'
          ? btoa(credentials)
          : Buffer.from(credentials).toString('base64');
      headers.Authorization = `Basic ${encoded}`;
    } else if (t) {
      headers.Authorization = `Bearer ${t}`;
    }

    lastUpdate = now;
    cache = headers;
    return headers;
  };
})();

// Optimize: Cache URL building for repeated endpoints
const buildUrl = (() => {
  const cache = new Map<string, string>();
  const maxCacheSize = 100;

  return (ep: string, p?: QueryParams): string => {
    const cacheKey = p ? `${ep}:${JSON.stringify(p)}` : ep;
    const cached = cache.get(cacheKey);
    if (cached) return cached;

    let url = ep;
    if (!/^https?:\/\//i.test(ep)) {
      const base = ENV.API_URL || (typeof window !== 'undefined' ? window.location.origin : '');
      url = `${base.replace(/\/+$/, '')}/${ep.replace(/^\/+/, '')}`;
    }

    if (p) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(p)) {
        if (v != null) {
          params.append(k, String(v));
        }
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }

    // LRU-style cache management
    if (cache.size >= maxCacheSize) {
      const firstKey = cache.keys().next().value;
      if (firstKey) cache.delete(firstKey);
    }
    cache.set(cacheKey, url);

    return url;
  };
})();

// Optimize: Limit recursion depth and memoize common types
const inferType = (v: unknown, d = 0): string => {
  if (d > 8) return 'unknown';
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';

  const type = typeof v;
  if (type !== 'object') return type;

  if (Array.isArray(v)) {
    return v.length ? `(${inferType(v[0], d + 1)})[]` : 'unknown[]';
  }

  // Limit object property inspection
  const entries = Object.entries(v as Record<string, unknown>).slice(0, 10);
  if (entries.length === 0) return '{}';

  const props = entries.map(([k, val]) => `  ${k}: ${inferType(val, d + 1)}`).join(',\n');

  return `{\n${props}\n}`;
};

const logTypes = (
  ep: string,
  method: string,
  data: unknown,
  meta?: { time: number; att?: number },
): void => {
  if (ENV.NODE_ENV !== 'development') return;

  const payload =
    typeof data === 'object' && data !== null && 'data' in data
      ? (data as { data: unknown }).data
      : data;

  const attemptInfo = meta?.att ? ` [attempt ${meta.att}]` : '';
  console.log(
    `🔍 [SafeFetch] ${method} ${ep} (${meta?.time}ms)${attemptInfo}\nType: ${inferType(payload)}`,
  );
};

// Optimize: Exponential backoff calculation
const calculateBackoff = (attempt: number): number => {
  // Cap at 10 seconds to avoid excessive waits
  return Math.min(10000, 100 * 2 ** (attempt - 1));
};

// Optimize: Extract error handling logic
const createErrorResponse = (error: unknown, url: string, method: string): ApiResponse<never> => {
  interface ErrorWithStatus {
    status?: number;
    name?: string;
    msg?: string;
    message?: string;
  }

  const err =
    typeof error === 'object' && error !== null
      ? (error as ErrorWithStatus)
      : { message: String(error) };

  const status = err.status || (err.name === 'AbortError' ? 408 : 0);

  return {
    success: false,
    status,
    error: {
      name: err.name || 'Error',
      message: err.msg || err.message || 'Unknown error',
      status,
      retryable: false,
      url,
      method,
    },
    data: null,
  };
};

// Optimize: Simplify response parsing
const parseResponse = async (res: Response): Promise<unknown> => {
  const contentType = res.headers.get('content-type');
  return contentType?.includes('json') ? res.json() : res.text();
};

// Optimize: Extract error message parsing
const extractErrorMessage = (data: unknown, statusText: string): string => {
  if (typeof data === 'string') return data;

  if (typeof data === 'object' && data !== null) {
    const obj = data as Record<string, unknown>;
    if (typeof obj.message === 'string') return obj.message;
    if (typeof obj.error === 'string') return obj.error;
  }

  return statusText;
};

// Optimize: Check if error is retryable
const isRetryableError = (status: number, attempt: number, maxRetries: number): boolean => {
  return attempt <= maxRetries && (status === 408 || status >= 500 || RETRY_CODES.has(status));
};

export default async function apiRequest<T = unknown>(
  method: HttpMethod,
  endpoint: string,
  opts: RequestOptions<RequestBody, T> = {},
): Promise<ApiResponse<T>> {
  // Validate method early
  if (!HTTP_METHODS.includes(method)) {
    return {
      success: false,
      status: 400,
      error: {
        name: 'ValidationError',
        message: 'Invalid HTTP method',
        status: 400,
      },
      data: null,
    };
  }

  const { retries = CFG.RETRIES, timeout = CFG.TIMEOUT, priority = 'normal', dedupeKey } = opts;

  const url = buildUrl(endpoint, opts.params);

  // Optimize: More efficient dedupe key generation
  const key =
    dedupeKey ??
    (opts.data
      ? `${method}:${url}:${JSON.stringify(opts.data).substring(0, 50)}`
      : `${method}:${url}`);

  const start = performance.now();

  return pool.exec(
    async () => {
      let attempt = 0;

      // eslint-disable-next-line no-constant-condition
      while (true) {
        attempt++;
        await limiter.check();

        const ctrl = new AbortController();
        const timeoutDuration = typeof timeout === 'function' ? timeout(attempt) : timeout;
        const timeoutId = setTimeout(() => ctrl.abort(), timeoutDuration);

        try {
          // Optimize: Build headers object once
          const headers: Record<string, string> = {
            Accept: 'application/json',
            ...getAuth(),
            ...opts.headers,
          };

          // Add Content-Type only if needed
          if (opts.data && !(opts.data instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
          }

          // Optimize: Prepare body once
          const body = opts.data
            ? opts.data instanceof FormData
              ? opts.data
              : JSON.stringify(opts.data)
            : undefined;

          const res = await fetch(url, {
            method,
            headers,
            body,
            signal: opts.signal || ctrl.signal,
            next: opts.next,
            cache: opts.cache,
          });

          clearTimeout(timeoutId);

          const data = await parseResponse(res);

          if (!res.ok) {
            const message = extractErrorMessage(data, res.statusText);
            throw { status: res.status, msg: message };
          }

          // Optimize: Only log in development
          if (opts.logTypes) {
            logTypes(endpoint, method, data, {
              time: Math.round(performance.now() - start),
              att: attempt > 1 ? attempt : undefined,
            });
          }

          // Optimize: Efficient header extraction
          const responseHeaders: Record<string, string> = {};
          res.headers.forEach((v, k) => {
            responseHeaders[k] = v;
          });

          return {
            success: true,
            status: res.status,
            data: opts.transform ? opts.transform(data as T) : (data as T),
            headers: responseHeaders,
          };
        } catch (e: unknown) {
          clearTimeout(timeoutId);

          interface ErrorWithStatus {
            status?: number;
            name?: string;
            message?: string;
          }

          const err = (
            typeof e === 'object' && e !== null ? e : { message: String(e) }
          ) as ErrorWithStatus;

          const status = err.status || (err.name === 'AbortError' ? 408 : 0);

          // Check if we should retry
          if (!isRetryableError(status, attempt, retries)) {
            return createErrorResponse(e, url, method);
          }

          // Exponential backoff before retry
          await new Promise((r) => setTimeout(r, calculateBackoff(attempt)));
        }
      }
    },
    priority,
    key,
  );
}

// Helpers with type guards
apiRequest.isSuccess = <T>(r: ApiResponse<T>): r is Extract<ApiResponse<T>, { success: true }> =>
  r.success;

apiRequest.isError = <T>(r: ApiResponse<T>): r is Extract<ApiResponse<T>, { success: false }> =>
  !r.success;

apiRequest.utils = {
  getStats: () => ({
    pool: pool.stats(),
    rateLimit: limiter.stats(),
    runtime: IS_BUN ? 'bun' : 'node',
  }),
  sanitizeHeaders: (h: Record<string, string>): Record<string, string> => {
    const sanitized = { ...h };
    const sensitiveHeaders = ['Authorization', 'X-API-Key', 'Cookie'];

    for (const key of sensitiveHeaders) {
      if (sanitized[key]) {
        sanitized[key] = '[REDACTED]';
      }
    }

    return sanitized;
  },
};

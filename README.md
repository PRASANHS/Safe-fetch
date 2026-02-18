# 🛡️ SafeFetch

> **Optimized Typed Fetch utility for Next.js 16 & Bun.**
> A memory-optimized HTTP client featuring priority-based pooling, adaptive rate limiting, and recursive type inference.
---

## Key Features

* **Priority-Based Pooling**: Internal queue handles concurrent requests based on importance (`high`, `normal`, `low`).
* **Bun-Optimized**: Automatically detects the **Bun** runtime to scale concurrency (20 tasks vs 10 in Node).
* **Smart Retries**: Automatic exponential backoff for specific status codes (`408`, `429`, `500-504`).
* **Adaptive Rate Limiting**: Built-in sliding window limiter (default: 100 req/min) with intelligent queuing.
* **Request Deduplication**: Identical concurrent requests are merged into one network call to prevent over-fetching.
* **Live Type Inference**: (Dev Only) Recursively inspects API responses and logs ready-to-use TypeScript interfaces.
* **Unified Auth**: Automated Bearer and Basic Auth injection with 5-minute credential caching.

---

## Quick Start

```typescript
import apiRequest from '@/lib/safe-fetch';

interface User {
  id: string;
  name: string;
}

const response = await apiRequest<User>('GET', '/api/user/1');

if (apiRequest.isSuccess(response)) {
  console.log(response.data.name); 
}

```

---

## RequestOptions: Complete Usage Guide

The `RequestOptions` object allows you to fine-tune every aspect of the network request. Below are examples for every property available in the 2025 implementation.

### 1. `data` (The Payload)

Supports JSON objects, `FormData` (for file uploads), or raw strings.

```typescript
// JSON Data
await apiRequest('POST', '/users', { data: { name: 'John Doe' } });

// FormData (File Upload)
const form = new FormData();
form.append('avatar', fileBlob);
await apiRequest('POST', '/upload', { data: form });

```

### 2. `params` (Query Parameters)

Automatically serializes objects into URL search strings, filtering out `null` or `undefined` values.

```typescript
await apiRequest('GET', '/posts', { 
  params: { page: 1, limit: 10, search: 'NextJS', archived: false } 
});
// Result: /posts?page=1&limit=10&search=NextJS&archived=false

```

### 3. `priority` (Pool Management)

Determines the order of execution in the internal queue.

```typescript
// Jump to the front of the queue
await apiRequest('GET', '/critical-config', { priority: 'high' });

// Process only when the system is idle
await apiRequest('POST', '/telemetry', { priority: 'low' });

```

### 4. `dedupeKey` (Request Merging)

Prevents redundant calls. If a request with the same key is already in-flight, SafeFetch returns that existing promise instead of hitting the network again.

```typescript
// Multiple components can call this simultaneously safely
await apiRequest('GET', '/settings', { dedupeKey: 'global-settings-key' });

```

### 5. `skipAuth` (Authentication Bypass)

Ignores global environment credentials (Bearer/Basic) for this specific call. Useful for external public APIs.

```typescript
await apiRequest('GET', 'https://api.github.com/zen', { skipAuth: true });

```

### 6. `logTypes` (Development Tool)

Recursively inspects the JSON response and logs a copy-pasteable TypeScript interface to the console.

```typescript
// Only works in process.env.NODE_ENV === 'development'
await apiRequest('GET', '/api/user/profile', { logTypes: true });

```

### 7. `timeout` (Adaptive or Fixed)

Accepts a number (ms) or a function that calculates timeout based on the retry attempt.

```typescript
await apiRequest('GET', '/unstable-api', { 
  timeout: (attempt) => attempt * 5000 // 5s, then 10s, then 15s...
});

```

### 8. `retries` (Retry Logic)

Overrides the default (2) retries for idempotent operations.

```typescript
await apiRequest('GET', '/vital-resource', { retries: 5 });

```

### 9. `transform` (Data Post-Processing)

Modify data after a successful fetch but before the application receives it.

```typescript
await apiRequest<User>('GET', '/user/1', {
  transform: (data) => ({
    ...data,
    displayName: data.nickname || data.name
  })
});

```

### 10. `headers` (Custom Headers)

Merge custom headers with SafeFetch's auto-generated headers (like Content-Type and Auth).

```typescript
await apiRequest('GET', '/data', { 
  headers: { 'X-Project-ID': '99', 'Accept-Encoding': 'gzip' } 
});

```

### 11. `cache` & `next` (Next.js 16 Integration)

Full support for the Next.js extended fetch API for caching and revalidation tags.

```typescript
await apiRequest('GET', '/products', {
  cache: 'force-cache',
  next: { 
    revalidate: 3600, 
    tags: ['product-list', 'inventory'] 
  }
});

```

### 12. `signal` (Manual Cancellation)

Cancel a request manually using an `AbortController`.

```typescript
const controller = new AbortController();
const request = apiRequest('GET', '/huge-payload', { signal: controller.signal });

// Some logic triggers cancellation
controller.abort();

```

---

## Response Handling & Utilities

SafeFetch returns a discriminated union, making it impossible to access data without checking for success first.

```typescript
const res = await apiRequest<User>('GET', '/me');

if (apiRequest.isSuccess(res)) {
  // res.data is typed as User
  console.log(res.status, res.headers);
} else {
  // res.error contains name, message, status, and retryable flag
  console.error(res.error.message);
}

```

### System Monitoring

```typescript
const stats = apiRequest.utils.getStats();

console.log(stats.pool);      // { active: number, queued: number }
console.log(stats.rateLimit); // { current: number }
console.log(stats.runtime);   // "bun" | "node"

```

---

## Environment Variables

SafeFetch reads these keys for its internal `getEnv` utility:

| Variable | Description |
| --- | --- |
| `NEXT_PUBLIC_API_URL` | Base API URL for relative paths. |
| `API_TOKEN` | Injected as `Authorization: Bearer <token>`. |
| `AUTH_USERNAME` / `AUTH_PASSWORD` | Injected as `Authorization: Basic <base64>`. |

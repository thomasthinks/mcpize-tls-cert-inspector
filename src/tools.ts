/**
 * Pure tool functions — business logic only, no MCP dependency.
 * Input validation (Zod) lives in src/schemas.ts; tool registration in index.ts.
 * Each function is unit-testable without MCP infrastructure.
 */

import {
  sanitizeHostname,
  inspectHost,
  consumeQuota,
  quotaErrorPayload,
  CertInspectionResult,
} from "./lib/tls.js";

// ---------------------------------------------------------------------------
// inspect_cert
// ---------------------------------------------------------------------------

export interface ToolError {
  [key: string]: unknown;
  isError: true;
  content: Array<{ type: "text"; text: string }>;
}

/** Type guard: distinguishes ToolError from success results (index signatures defeat `in` narrowing). */
export function isToolError(output: unknown): output is ToolError {
  return (
    typeof output === "object" &&
    output !== null &&
    (output as { isError?: unknown }).isError === true
  );
}

function toolError(error: unknown, suggestion: string): ToolError {
  const message = error instanceof Error ? error.message : String(error);
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify({ error: message, suggestion }),
      },
    ],
  };
}

/** Single-host certificate inspection. Inputs must already be Zod-validated. */
export async function inspectCert(
  hostnameRaw: string,
  port: number
): Promise<CertInspectionResult | ToolError> {
  let hostname: string;
  try {
    hostname = sanitizeHostname(hostnameRaw);
  } catch (err) {
    return toolError(err, 'Provide a plain DNS hostname like "example.com" (no protocol, port, or path).');
  }

  if (!consumeQuota(1)) {
    return toolError(
      new Error(quotaErrorPayload().error as string),
      quotaErrorPayload().suggestion as string
    );
  }

  try {
    return await inspectHost(hostname, port);
  } catch (err) {
    return toolError(
      err,
      `Check that "${hostname}" is spelled correctly and port ${port} accepts TLS traffic on that host.`
    );
  }
}

// ---------------------------------------------------------------------------
// check_expiry_bulk
// ---------------------------------------------------------------------------

export const MAX_BULK_HOSTS = 20;
export const BULK_CONCURRENCY = 5;

export interface BulkHostResult {
  [key: string]: unknown;
  hostname: string;
  valid_to?: string;
  days_remaining?: number;
  expired?: boolean;
  issuer?: string;
  cached?: boolean;
  error?: string;
}

export interface BulkResult {
  [key: string]: unknown;
  results: BulkHostResult[];
  warnings: {
    critical: string[]; // <7 days remaining (includes expired)
    warning: string[]; // 7–29 days remaining
  };
  checked_at: string;
}

/** Pure summarization: sort + warning buckets. Easy to unit test. */
export function summarizeBulk(entries: BulkHostResult[], checkedAt: string): BulkResult {
  const ok = entries.filter((e) => e.error === undefined);
  const failed = entries.filter((e) => e.error !== undefined);

  ok.sort((a, b) => (a.days_remaining ?? Infinity) - (b.days_remaining ?? Infinity));

  const critical: string[] = [];
  const warning: string[] = [];
  for (const e of ok) {
    const days = e.days_remaining ?? Infinity;
    if (days < 7) critical.push(e.hostname);
    else if (days < 30) warning.push(e.hostname);
  }

  return {
    results: [...ok, ...failed],
    warnings: { critical, warning },
    checked_at: checkedAt,
  };
}

async function inspectOneForBulk(hostnameRaw: string, port: number): Promise<BulkHostResult> {
  let hostname: string;
  try {
    hostname = sanitizeHostname(hostnameRaw);
  } catch (err) {
    return {
      hostname: String(hostnameRaw),
      error: err instanceof Error ? err.message : String(err),
    };
  }
  try {
    const full: CertInspectionResult = await inspectHost(hostname, port);
    return {
      hostname: full.hostname,
      valid_to: full.valid_to,
      days_remaining: full.days_remaining,
      expired: full.expired,
      issuer: full.issuer,
      cached: full.cached,
    };
  } catch (err) {
    return {
      hostname,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Inspect up to 20 hosts' certificates, sorted by days_remaining ascending.
 * Concurrency is capped at 5; per-host failures become {hostname, error}
 * entries — the batch never fails wholesale.
 */
export async function checkExpiryBulk(
  hostnamesRaw: string[],
  port: number
): Promise<BulkResult | ToolError> {
  if (!consumeQuota(1)) {
    return toolError(
      new Error(quotaErrorPayload().error as string),
      quotaErrorPayload().suggestion as string
    );
  }

  // Dedupe after sanitization so one bad entry doesn't kill the batch;
  // keep the raw value for error entries.
  const seen = new Set<string>();
  const queue: Array<{ raw: string; key: string }> = [];
  for (const raw of hostnamesRaw) {
    let key: string;
    try {
      key = sanitizeHostname(raw).toLowerCase();
    } catch {
      queue.push({ raw, key: `__invalid__:${raw}` });
      continue;
    }
    if (seen.has(key)) continue;
    seen.add(key);
    queue.push({ raw, key });
  }

  const results: BulkHostResult[] = new Array(queue.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < queue.length) {
      const i = next++;
      const item = queue[i] as { raw: string; key: string };
      results[i] = await inspectOneForBulk(item.raw, port);
    }
  }
  const workers = Array.from(
    { length: Math.min(BULK_CONCURRENCY, queue.length) },
    () => worker()
  );
  await Promise.all(workers);

  return summarizeBulk(results, new Date().toISOString());
}

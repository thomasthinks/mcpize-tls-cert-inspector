/**
 * Zod input schemas — shared between tool registration (src/index.ts)
 * and unit tests. Every field carries a .describe() for LLM consumers.
 */
import { z } from "zod";
import { sanitizeHostname } from "./lib/tls.js";
import { MAX_BULK_HOSTS } from "./tools.js";

/**
 * Non-throwing sanitize for use inside Zod transforms (zod v4 classic does
 * not convert transform throws into validation issues). Returns null on garbage.
 */
function trySanitizeHostname(raw: string): string | null {
  try {
    return sanitizeHostname(raw);
  } catch {
    return null;
  }
}

/**
 * Hostname field: strips protocol/credentials/port/path, lowercases, then
 * validates against the hostname regex. Garbage input becomes a Zod issue
 * with a helpful message (never a thrown exception).
 */
export const HostnameSchema = z
  .string()
  .min(1)
  .max(253)
  .describe(
    'Hostname to inspect, e.g. "example.com". Protocol, port, and path are stripped automatically ("https://example.com/path" works too).'
  )
  .transform((raw): string | null => trySanitizeHostname(raw))
  .refine((v): v is string => v !== null, {
    message:
      'Invalid hostname — use a plain DNS hostname like "example.com" (no protocol, port, or path).',
  });

export const PortSchema = z
  .number()
  .int()
  .min(1)
  .max(65535)
  .optional()
  .default(443)
  .describe("TLS port to connect to. Defaults to 443.");

export const InspectCertInputSchema = z.object({
  hostname: HostnameSchema,
  port: PortSchema,
});

export const BulkInputSchema = z.object({
  hostnames: z
    .array(HostnameSchema)
    .min(1)
    .max(MAX_BULK_HOSTS)
    .describe(
      `List of hostnames to inspect (1–${MAX_BULK_HOSTS}). Duplicates are checked once. Failed hosts appear as {hostname, error} entries and never fail the batch.`
    ),
  port: PortSchema,
});

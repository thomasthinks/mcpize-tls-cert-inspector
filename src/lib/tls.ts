/**
 * Live TLS certificate inspection via Node's built-in tls module.
 *
 * No upstream API, no cost: everything here is a live TLS handshake plus
 * local parsing of the presented certificate. All code is original.
 */

import * as tls from "tls";
import * as net from "net";
import { isIP } from "net";

// ---------------------------------------------------------------------------
// Input sanitization
// ---------------------------------------------------------------------------

const HOSTNAME_RE =
  /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Normalize a raw hostname input: strip protocol/credentials/port/path,
 * lowercase, then validate against a hostname regex (or allow IP literals).
 * Throws a human-friendly Error on garbage input.
 */
export function sanitizeHostname(raw: string): string {
  let s = String(raw ?? "").trim().toLowerCase();
  if (!s) {
    throw new Error(
      'Invalid hostname: input is empty. Provide a plain DNS hostname like "example.com".'
    );
  }
  // Strip scheme (https://, tcp://, ...)
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  // Strip credentials user:pass@
  const at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);
  if (s.startsWith("[")) {
    // IPv6 literal, e.g. [::1]:443
    const close = s.indexOf("]");
    if (close === -1) {
      throw new Error(
        `Invalid hostname "${raw}" — unbalanced bracket in IPv6 literal. Example: "[::1]:443".`
      );
    }
    s = s.slice(1, close);
  } else {
    // Strip path / query / fragment
    s = s.split(/[/?#]/, 1)[0];
    // Strip :port (only when a single colon, so we don't mangle IPv6)
    if (s.indexOf(":") === s.lastIndexOf(":")) {
      const colon = s.indexOf(":");
      if (colon !== -1) s = s.slice(0, colon);
    }
  }
  s = s.trim();
  if (!s || !(HOSTNAME_RE.test(s) || isIP(s) !== 0)) {
    throw new Error(
      `Invalid hostname "${raw}" — use a plain DNS hostname like "example.com" (no protocol, port, or path).`
    );
  }
  return s;
}

// ---------------------------------------------------------------------------
// Certificate parsing helpers
// ---------------------------------------------------------------------------

export const MAX_SAN_ENTRIES = 50;
export const DAY_MS = 24 * 60 * 60 * 1000;

type CertLike = {
  subject?: Record<string, string> | null;
  issuer?: Record<string, string> | null;
  valid_from?: string;
  valid_to?: string;
  subjectaltname?: string;
  [key: string]: unknown;
};

function formatIssuer(issuer?: Record<string, string> | null): string {
  if (!issuer || typeof issuer !== "object") return "unknown";
  if (issuer.CN) return String(issuer.CN);
  if (issuer.O) return String(issuer.O);
  const parts = Object.entries(issuer).map(([k, v]) => `${k}=${v}`);
  return parts.length > 0 ? parts.join(", ") : "unknown";
}

/** Parse a subjectAltName string ("DNS:a.com, DNS:b.com, IP Address:1.2.3.4") into DNS names, capped at 50. */
export function parseSan(subjectAltName?: string): string[] {
  if (!subjectAltName) return [];
  const names: string[] = [];
  for (const part of subjectAltName.split(",")) {
    const trimmed = part.trim();
    const m = /^DNS:(.+)$/i.exec(trimmed);
    if (m && m[1]) names.push(m[1].trim());
    if (names.length >= MAX_SAN_ENTRIES) break;
  }
  return names;
}

/** Whole-day expiry math: floor of remaining days. A cert with 5.5 hours left reports 0. */
export function daysRemaining(validToIso: string, nowMs: number = Date.now()): number {
  const to = Date.parse(validToIso);
  if (Number.isNaN(to)) return NaN;
  return Math.floor((to - nowMs) / DAY_MS);
}

export function isExpired(validToIso: string, nowMs: number = Date.now()): boolean {
  const to = Date.parse(validToIso);
  if (Number.isNaN(to)) return false;
  return nowMs >= to;
}

// ---------------------------------------------------------------------------
// Live TLS handshakes
// ---------------------------------------------------------------------------

export const HANDSHAKE_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Optional egress-proxy support (standard HTTPS_PROXY / NO_PROXY semantics)
// ---------------------------------------------------------------------------

/**
 * Return a proxy URL if TLS traffic to this hostname should be tunnelled
 * through an egress proxy (HTTP CONNECT). Direct connection otherwise.
 * This is a no-op in environments without proxy env vars (e.g. MCPize Cloud).
 */
function getProxyFor(hostname: string): URL | undefined {
  if (isIP(hostname) !== 0) return undefined; // never proxy IP literals
  const noProxy = (process.env.NO_PROXY ?? process.env.no_proxy ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const lower = hostname.toLowerCase();
  for (const entry of noProxy) {
    if (entry === "*" || lower === entry || lower.endsWith("." + entry.replace(/^\./, ""))) {
      return undefined;
    }
  }
  const raw =
    process.env.HTTPS_PROXY ?? process.env.https_proxy ?? process.env.ALL_PROXY ?? process.env.all_proxy;
  if (!raw) return undefined;
  try {
    return new URL(raw);
  } catch {
    return undefined;
  }
}

/** Open a raw TCP tunnel to hostname:port via HTTP CONNECT on the proxy. */
function connectViaProxy(proxy: URL, hostname: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      reject(err);
    };
    const timer = setTimeout(
      () => fail(new Error(`Proxy CONNECT to ${hostname}:${port} timed out`)),
      timeoutMs
    );

    const sock = net.connect(parseInt(proxy.port || "80", 10), proxy.hostname);
    sock.on("error", fail);

    sock.on("connect", () => {
      let req = `CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n`;
      if (proxy.username) {
        const creds = Buffer.from(
          `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`
        ).toString("base64");
        req += `Proxy-Authorization: Basic ${creds}\r\n`;
      }
      req += "Connection: close\r\n\r\n";
      sock.write(req);
    });

    let head = "";
    const onData = (chunk: Buffer) => {
      head += chunk.toString("latin1");
      const idx = head.indexOf("\r\n\r\n");
      if (idx === -1) return;
      sock.off("data", onData);
      const statusLine = head.slice(0, idx).split("\r\n")[0] ?? "";
      const status = parseInt(statusLine.split(" ")[1] ?? "", 10);
      if (status === 200) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(sock);
      } else {
        fail(new Error(`Proxy refused CONNECT to ${hostname}:${port} (status ${status || "unknown"})`));
      }
    };
    sock.on("data", onData);
  });
}

function connectOnce(
  opts: tls.ConnectionOptions,
  preconnected: net.Socket | undefined,
  timeoutMs: number
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`TLS handshake timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);

    const connectOpts: tls.ConnectionOptions = preconnected
      ? {
          socket: preconnected,
          servername: opts.servername,
          rejectUnauthorized: opts.rejectUnauthorized,
        }
      : opts;
    const socket = tls.connect(connectOpts, () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(socket);
    });
    socket.on("error", (err: Error & { code?: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    });
  });
}

function friendlyConnectError(hostname: string, port: number, err: Error & { code?: string }): Error {
  const code = err.code ?? "";
  if (code === "ENOTFOUND" || code === "EAI_AGAIN") {
    return new Error(
      `Could not resolve "${hostname}". Check the spelling, or try the domain's www/non-www variant.`
    );
  }
  if (code === "ECONNREFUSED" || code === "EHOSTUNREACH" || code === "ENETUNREACH") {
    return new Error(
      `Could not reach ${hostname}:${port} (connection ${code.toLowerCase()}). Verify the host is up and port ${port} accepts TLS traffic.`
    );
  }
  if (/timed out/i.test(err.message)) {
    return new Error(
      `Timed out connecting to ${hostname}:${port} after ${HANDSHAKE_TIMEOUT_MS / 1000}s. The host may be firewalled or very slow — retry, or pass an explicit port if the service runs on a non-standard one.`
    );
  }
  return new Error(
    `TLS handshake with ${hostname}:${port} failed (${code || err.message}). The host may not speak TLS on this port — try an explicit port if the service runs on a non-standard one.`
  );
}

export interface RawInspection {
  cert: CertLike;
  tlsVersion: string;
  chainComplete: boolean;
}

/**
 * Perform the two handshakes:
 *  1. rejectUnauthorized:false + SNI -> capture the presented cert even from
 *     misconfigured/self-signed/expired hosts.
 *  2. authorized attempt -> chainComplete is true only if the default system
 *     trust store accepts the chain for this hostname.
 */
export async function performHandshake(hostname: string, port: number): Promise<RawInspection> {
  const deadline = Date.now() + HANDSHAKE_TIMEOUT_MS;
  const remaining = () => Math.max(1000, deadline - Date.now());
  const baseOpts = (rejectUnauthorized: boolean): tls.ConnectionOptions => ({
    host: hostname,
    port,
    servername: isIP(hostname) ? undefined : hostname, // SNI only for DNS names
    rejectUnauthorized,
  });
  const proxy = getProxyFor(hostname);

  // First handshake: capture the presented cert even from misconfigured hosts.
  // One retry on transient socket errors (ECONNRESET/EPIPE/timeouts) — the
  // egress path can drop an occasional connection mid-handshake.
  let socket: tls.TLSSocket | undefined;
  let lastError: (Error & { code?: string }) | undefined;
  for (let attempt = 0; attempt < 2 && !socket; attempt++) {
    let tunnel: net.Socket | undefined;
    try {
      // Optional egress-proxy tunnel (no-op without proxy env vars).
      if (proxy) tunnel = await connectViaProxy(proxy, hostname, port, remaining());
      socket = await connectOnce(baseOpts(false), tunnel, remaining());
    } catch (err) {
      tunnel?.destroy();
      lastError = err as Error & { code?: string };
      const transient =
        /timed out/i.test(lastError.message) ||
        ["ECONNRESET", "EPIPE", "ETIMEDOUT"].includes(lastError.code ?? "");
      if (!transient) break;
    }
  }
  if (!socket) {
    throw friendlyConnectError(hostname, port, lastError ?? new Error("unknown connection failure"));
  }

  let cert: tls.PeerCertificate;
  let tlsVersion: string;
  try {
    cert = socket.getPeerCertificate(true);
    tlsVersion = socket.getProtocol() ?? "unknown";
  } finally {
    socket.destroy();
  }
  if (!cert || Object.keys(cert).length === 0) {
    throw new Error(
      `No TLS certificate was presented by ${hostname}:${port}. The service may speak plain HTTP or another protocol on this port.`
    );
  }

  // Second handshake: authorized, to test the chain against the system trust store.
  let chainComplete = false;
  try {
    let authTunnel: net.Socket | undefined;
    if (proxy) authTunnel = await connectViaProxy(proxy, hostname, port, remaining());
    const authSocket = await connectOnce(baseOpts(true), authTunnel, remaining());
    authSocket.destroy();
    chainComplete = true;
  } catch {
    chainComplete = false;
  }

  return { cert: cert as unknown as CertLike, tlsVersion, chainComplete };
}

// ---------------------------------------------------------------------------
// In-memory cache (1h TTL)
// ---------------------------------------------------------------------------

export const CACHE_TTL_MS = 60 * 60 * 1000;

interface CacheEntry {
  ts: number;
  data: CertInspectionResult;
}

const cache = new Map<string, CacheEntry>();

export function cacheKey(hostname: string, port: number): string {
  return `${hostname}:${port}`;
}

export function getCached(hostname: string, port: number): CertInspectionResult | undefined {
  const entry = cache.get(cacheKey(hostname, port));
  if (!entry) return undefined;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    cache.delete(cacheKey(hostname, port));
    return undefined;
  }
  return entry.data;
}

export function setCached(hostname: string, port: number, data: CertInspectionResult): void {
  cache.set(cacheKey(hostname, port), { ts: Date.now(), data });
}

/** Test hook: clear the cache. */
export function __resetCacheForTests(): void {
  cache.clear();
}

// ---------------------------------------------------------------------------
// Freemium usage tracking (in-memory, per UTC day)
// ---------------------------------------------------------------------------

export function getFreeDailyLimit(): number {
  const raw = process.env.FREE_DAILY_LIMIT;
  const parsed = raw ? parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 100;
}

const usageByDay = new Map<string, number>();

function todayKey(): string {
  return new Date().toISOString().slice(0, 10); // UTC date
}

/** Returns true if the call is allowed (and records it), false if quota is exhausted. */
export function consumeQuota(units = 1): boolean {
  const key = todayKey();
  const used = usageByDay.get(key) ?? 0;
  if (used + units > getFreeDailyLimit()) return false;
  usageByDay.set(key, used + units);
  return true;
}

export function quotaErrorPayload(): Record<string, unknown> {
  return {
    error: `Free quota exceeded (${getFreeDailyLimit()}/day). Pay-per-call available via x402.`,
    suggestion: "Try again tomorrow, or use the x402 pay-per-call option at $0.01/call.",
  };
}

/** Test hook: clear usage counters. */
export function __resetUsageForTests(): void {
  usageByDay.clear();
}

// ---------------------------------------------------------------------------
// Public result types + pure inspection builder
// ---------------------------------------------------------------------------

export interface CertInspectionResult {
  [key: string]: unknown;
  hostname: string;
  port: number;
  subject_cn: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  days_remaining: number;
  expired: boolean;
  san: string[];
  tls_version_negotiated: string;
  chain_complete: boolean;
  cached: boolean;
}

export function buildInspection(
  hostname: string,
  port: number,
  raw: RawInspection,
  cached: boolean
): CertInspectionResult {
  const cert = raw.cert;
  const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : "unknown";
  const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : "unknown";
  const days = cert.valid_to ? daysRemaining(validTo) : NaN;
  const expired = cert.valid_to ? isExpired(validTo) : false;
  const subject = (cert.subject ?? {}) as Record<string, string>;

  return {
    hostname,
    port,
    subject_cn: subject.CN ?? "",
    issuer: formatIssuer(cert.issuer),
    valid_from: validFrom,
    valid_to: validTo,
    days_remaining: days,
    expired,
    san: parseSan(cert.subjectaltname),
    tls_version_negotiated: raw.tlsVersion,
    chain_complete: raw.chainComplete,
    cached,
  };
}

/**
 * Inspect a single host's TLS certificate. Uses the 1h in-memory cache.
 * Throws on network/TLS errors (callers wrap into isError responses).
 */
export async function inspectHost(hostname: string, port: number): Promise<CertInspectionResult> {
  const hit = getCached(hostname, port);
  if (hit) {
    return { ...hit, cached: true };
  }
  const raw = await performHandshake(hostname, port);
  const result = buildInspection(hostname, port, raw, false);
  setCached(hostname, port, result);
  return result;
}

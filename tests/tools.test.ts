/**
 * Unit + integration tests for tls-cert-inspector.
 *
 * - Pure logic (sanitize/parse/expiry/sort) is tested hermetically.
 * - Cert parsing is tested against a locally minted self-signed cert
 *   served by a local TLS server (openssl CLI in beforeAll).
 * - Live hosts (google.com, expired.badssl.com) verify real handshakes.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { execFileSync } from "child_process";
import * as tls from "tls";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { AddressInfo } from "net";

import {
  sanitizeHostname,
  parseSan,
  daysRemaining,
  isExpired,
  buildInspection,
  __resetCacheForTests,
  __resetUsageForTests,
  MAX_SAN_ENTRIES,
} from "../src/lib/tls.js";
import { inspectCert, checkExpiryBulk, summarizeBulk, isToolError } from "../src/tools.js";
import { InspectCertInputSchema, BulkInputSchema } from "../src/schemas.js";

// ---------------------------------------------------------------------------
// Local TLS fixtures: mint a self-signed cert, serve it on 127.0.0.1
// ---------------------------------------------------------------------------

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tls-cert-inspector-test-"));
let localPort = 0;
let localServer: tls.Server;

function mintValidCert(): { key: string; cert: string } {
  const keyPath = path.join(tmpDir, "key.pem");
  const certPath = path.join(tmpDir, "cert.pem");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "365",
    "-nodes",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost,DNS:example.local",
  ]);
  return {
    key: fs.readFileSync(keyPath, "utf8"),
    cert: fs.readFileSync(certPath, "utf8"),
  };
}

beforeAll(async () => {
  const { key, cert } = mintValidCert();
  localServer = tls.createServer({ key, cert }, (socket) => {
    // Handshake is complete by the time we get here; just hang up.
    socket.end();
  });
  await new Promise<void>((resolve) => localServer.listen(0, "127.0.0.1", resolve));
  localPort = (localServer.address() as AddressInfo).port;
}, 30000);

afterAll(async () => {
  await new Promise<void>((resolve) => localServer.close(() => resolve()));
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

beforeEach(() => {
  __resetCacheForTests();
  __resetUsageForTests();
  delete process.env.FREE_DAILY_LIMIT;
});

// ---------------------------------------------------------------------------
// sanitizeHostname
// ---------------------------------------------------------------------------

describe("sanitizeHostname", () => {
  it("strips protocol, port, and path", () => {
    expect(sanitizeHostname("https://Example.COM:8443/some/path?q=1")).toBe("example.com");
  });
  it("lowercases plain hostnames", () => {
    expect(sanitizeHostname("WWW.Google.COM")).toBe("www.google.com");
  });
  it("accepts subdomains and hyphens", () => {
    expect(sanitizeHostname("my-host.sub.example.co.uk")).toBe("my-host.sub.example.co.uk");
  });
  it("accepts IP literals", () => {
    expect(sanitizeHostname("127.0.0.1")).toBe("127.0.0.1");
  });
  it("rejects garbage with a helpful message", () => {
    expect(() => sanitizeHostname("not a host!!!")).toThrow(/Invalid hostname/);
    expect(() => sanitizeHostname("")).toThrow(/empty/);
    expect(() => sanitizeHostname("http://")).toThrow(/Invalid hostname/);
  });
});

// ---------------------------------------------------------------------------
// parseSan / daysRemaining / isExpired
// ---------------------------------------------------------------------------

describe("parseSan", () => {
  it("extracts DNS names and ignores IP entries", () => {
    expect(parseSan("DNS:example.com, DNS:www.example.com, IP Address:1.2.3.4")).toEqual([
      "example.com",
      "www.example.com",
    ]);
  });
  it("returns [] for missing/empty input", () => {
    expect(parseSan(undefined)).toEqual([]);
    expect(parseSan("")).toEqual([]);
  });
  it(`truncates at ${MAX_SAN_ENTRIES} entries`, () => {
    const many = Array.from({ length: 80 }, (_, i) => `DNS:h${i}.example.com`).join(", ");
    const parsed = parseSan(many);
    expect(parsed).toHaveLength(MAX_SAN_ENTRIES);
    expect(parsed[0]).toBe("h0.example.com");
  });
});

describe("expiry math", () => {
  const NOW = Date.parse("2026-10-04T00:00:00Z");
  it("floors partial days", () => {
    // 5.5 hours left -> 0 days remaining (not rounded up)
    expect(daysRemaining("2026-10-04T05:30:00Z", NOW)).toBe(0);
  });
  it("counts whole days", () => {
    expect(daysRemaining("2026-10-14T00:00:00Z", NOW)).toBe(10);
  });
  it("goes negative after expiry", () => {
    expect(daysRemaining("2026-10-01T00:00:00Z", NOW)).toBe(-3);
  });
  it("isExpired flips at the boundary", () => {
    expect(isExpired("2026-10-04T00:00:00Z", NOW)).toBe(true);
    expect(isExpired("2026-10-04T00:00:01Z", NOW)).toBe(false);
  });
});

describe("buildInspection", () => {
  it("parses a cert-shaped object including the expired case", () => {
    const result = buildInspection(
      "expired.local",
      443,
      {
        cert: {
          subject: { CN: "expired.local" },
          issuer: { C: "US", O: "BadSSL", CN: "BadSSL Expired CA" },
          valid_from: "2020-01-01T00:00:00Z",
          valid_to: "2020-01-02T00:00:00Z",
          subjectaltname: "DNS:expired.local",
        },
        tlsVersion: "TLSv1.3",
        chainComplete: false,
      },
      false
    );
    expect(result.subject_cn).toBe("expired.local");
    expect(result.issuer).toBe("BadSSL Expired CA");
    expect(result.expired).toBe(true);
    expect(result.days_remaining).toBeLessThan(0);
    expect(result.san).toEqual(["expired.local"]);
    expect(result.chain_complete).toBe(false);
    expect(result.tls_version_negotiated).toBe("TLSv1.3");
  });
});

// ---------------------------------------------------------------------------
// summarizeBulk (pure)
// ---------------------------------------------------------------------------

describe("summarizeBulk", () => {
  it("sorts by days_remaining ascending and buckets warnings", () => {
    const out = summarizeBulk(
      [
        { hostname: "a.com", days_remaining: 40, expired: false },
        { hostname: "b.com", days_remaining: 3, expired: false },
        { hostname: "c.com", days_remaining: 15, expired: false },
        { hostname: "d.com", days_remaining: -2, expired: true },
        { hostname: "e.com", error: "boom" },
      ],
      "2026-10-04T00:00:00Z"
    );
    expect(out.results.map((r) => r.hostname)).toEqual(["d.com", "b.com", "c.com", "a.com", "e.com"]);
    expect(out.warnings.critical).toEqual(["d.com", "b.com"]);
    expect(out.warnings.warning).toEqual(["c.com"]);
    expect(out.checked_at).toBe("2026-10-04T00:00:00Z");
  });
  it("keeps the 7/30 day boundaries exact", () => {
    const out = summarizeBulk(
      [
        { hostname: "x.com", days_remaining: 7, expired: false },
        { hostname: "y.com", days_remaining: 30, expired: false },
        { hostname: "z.com", days_remaining: 6, expired: false },
      ],
      "now"
    );
    expect(out.warnings.critical).toEqual(["z.com"]);
    expect(out.warnings.warning).toEqual(["x.com"]);
  });
});

// ---------------------------------------------------------------------------
// inspectCert — local self-signed fixture
// ---------------------------------------------------------------------------

describe("inspectCert (local self-signed server)", () => {
  it("parses the presented cert and marks the chain incomplete", async () => {
    const out = await inspectCert("127.0.0.1", localPort);
    if (isToolError(out)) throw new Error(`unexpected error: ${JSON.stringify(out.content)}`);
    expect(out.hostname).toBe("127.0.0.1");
    expect(out.port).toBe(localPort);
    expect(out.subject_cn).toBe("localhost");
    expect(out.issuer).toContain("localhost"); // self-signed: issuer == subject
    expect(out.days_remaining).toBeGreaterThan(0);
    expect(out.days_remaining).toBeLessThanOrEqual(365);
    expect(out.expired).toBe(false);
    expect(out.san).toContain("localhost");
    expect(out.san).toContain("example.local");
    expect(out.tls_version_negotiated).toMatch(/^TLSv1/);
    expect(out.chain_complete).toBe(false); // self-signed: authorized handshake fails
    expect(out.cached).toBe(false);
  }, 30000);

  it("serves the second identical call from cache", async () => {
    const first = await inspectCert("127.0.0.1", localPort);
    const second = await inspectCert("127.0.0.1", localPort);
    if (isToolError(first) || isToolError(second)) throw new Error("unexpected error");
    expect(first.cached).toBe(false);
    expect(second.cached).toBe(true);
    expect(second.subject_cn).toBe(first.subject_cn);
  }, 30000);
});

// ---------------------------------------------------------------------------
// inspectCert — live hosts
// ---------------------------------------------------------------------------

describe("inspectCert (live)", () => {
  it('returns real cert data for "google.com"', async () => {
    const out = await inspectCert("google.com", 443);
    if (isToolError(out)) throw new Error(`unexpected error: ${JSON.stringify(out.content)}`);
    expect(out.hostname).toBe("google.com");
    expect(out.days_remaining).toBeGreaterThan(0);
    expect(out.expired).toBe(false);
    expect(out.issuer.length).toBeGreaterThan(0);
    expect(out.chain_complete).toBe(true);
    expect(out.san.length).toBeGreaterThan(0);
  }, 30000);

  it('reports expired:true for "expired.badssl.com"', async () => {
    const out = await inspectCert("expired.badssl.com", 443);
    if (isToolError(out)) throw new Error(`unexpected error: ${JSON.stringify(out.content)}`);
    expect(out.expired).toBe(true);
    expect(out.days_remaining).toBeLessThan(0);
  }, 30000);

  it('returns an isError for garbage input "not a host!!!"', async () => {
    const out = await inspectCert("not a host!!!", 443);
    expect(isToolError(out)).toBe(true);
    if (isToolError(out)) {
      const body = JSON.parse(out.content[0].text) as { error: string; suggestion: string };
      expect(body.error).toMatch(/Invalid hostname/);
      expect(body.suggestion.length).toBeGreaterThan(0);
    }
  });

  it("rejects unreachable hosts with an LLM-friendly error", async () => {
    const out = await inspectCert("this-host-definitely-does-not-exist-xyz.invalid", 443);
    expect(isToolError(out)).toBe(true);
    if (isToolError(out)) {
      const body = JSON.parse(out.content[0].text) as { error: string; suggestion: string };
      expect(body.error).toMatch(/Could not resolve|Could not reach|Timed out|failed/i);
      expect(body.suggestion.length).toBeGreaterThan(0);
    }
  }, 30000);
});

// ---------------------------------------------------------------------------
// Zod input schemas
// ---------------------------------------------------------------------------

describe("input schemas", () => {
  it("rejects garbage hostnames at the schema boundary", () => {
    const parsed = InspectCertInputSchema.safeParse({ hostname: "not a host!!!" });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues[0].message).toMatch(/Invalid hostname/);
    }
  });
  it("normalizes messy-but-valid input and defaults the port", () => {
    const parsed = InspectCertInputSchema.safeParse({ hostname: "https://Example.COM/path" });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.hostname).toBe("example.com");
      expect(parsed.data.port).toBe(443);
    }
  });
  it("enforces the bulk array bounds", () => {
    expect(BulkInputSchema.safeParse({ hostnames: [] }).success).toBe(false);
    expect(
      BulkInputSchema.safeParse({ hostnames: Array.from({ length: 21 }, (_, i) => `h${i}.com`) })
        .success
    ).toBe(false);
    expect(BulkInputSchema.safeParse({ hostnames: ["a.com"] }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// checkExpiryBulk
// ---------------------------------------------------------------------------

describe("checkExpiryBulk", () => {
  it("sorts mixed live results and buckets warnings; failures stay as entries", async () => {
    const out = await checkExpiryBulk(
      ["google.com", "expired.badssl.com", "this-host-definitely-does-not-exist-xyz.invalid"],
      443
    );
    if (isToolError(out)) throw new Error(`unexpected error: ${JSON.stringify(out.content)}`);
    expect(out.results).toHaveLength(3);
    // expired.badssl.com (negative days) sorts first, failure entry sorts last
    expect(out.results[0].hostname).toBe("expired.badssl.com");
    expect(out.results[0].expired).toBe(true);
    expect(out.results[2].hostname).toBe("this-host-definitely-does-not-exist-xyz.invalid");
    expect(out.results[2].error).toBeDefined();
    expect(out.warnings.critical).toContain("expired.badssl.com");
    expect(Date.parse(out.checked_at)).not.toBeNaN();
  }, 60000);

  it("dedupes repeated hostnames into one check", async () => {
    const out = await checkExpiryBulk(["google.com", "google.com", "GOOGLE.COM"], 443);
    if (isToolError(out)) throw new Error(`unexpected error: ${JSON.stringify(out.content)}`);
    expect(out.results).toHaveLength(1);
    expect(out.results[0].hostname).toBe("google.com");
  }, 30000);
});

// ---------------------------------------------------------------------------
// Freemium quota
// ---------------------------------------------------------------------------

describe("free quota", () => {
  it("returns isError once the daily limit is exceeded", async () => {
    process.env.FREE_DAILY_LIMIT = "2";
    __resetUsageForTests();
    const ok1 = await inspectCert("127.0.0.1", localPort);
    const ok2 = await inspectCert("127.0.0.1", localPort);
    expect(isToolError(ok1)).toBe(false);
    expect(isToolError(ok2)).toBe(false);
    const over = await inspectCert("127.0.0.1", localPort);
    expect(isToolError(over)).toBe(true);
    if (isToolError(over)) {
      const body = JSON.parse(over.content[0].text) as { error: string };
      expect(body.error).toMatch(/Free quota exceeded \(2\/day\)/);
    }
  }, 30000);

  it("enforces the same quota on bulk checks", async () => {
    process.env.FREE_DAILY_LIMIT = "1";
    __resetUsageForTests();
    const first = await checkExpiryBulk(["google.com"], 443);
    expect(isToolError(first)).toBe(false);
    const second = await checkExpiryBulk(["google.com"], 443);
    expect(isToolError(second)).toBe(true);
  }, 60000);
});

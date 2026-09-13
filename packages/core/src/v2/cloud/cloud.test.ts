/**
 * Gateway v2 cloud — pairing lifecycle and §3.3 service shapes (spec
 * §3.2/§9.3): viewer-only authority, separately scoped remote_ui grant,
 * pinned providers only, no inbound listeners, queued remote notices
 * when the provider is unreachable.
 */
import { describe, expect, it } from "vitest";
import { F, H } from "@latticeag/testkit";
import type { NativeRef } from "../protocol/refs.js";
import { isPairCode } from "../crypto/ids.js";
import { createCloudService } from "./service.js";
import { createMemoryCloudPorts } from "./ports.js";
import type { MemoryCloudPorts } from "./ports.js";

function binding(id = "binding1"): NativeRef {
  return {
    profile: "cloud.binding/1",
    namespace: "hosted",
    object_id: id,
    commitment: "sha256:" + H(id),
    raw_sha256: H(`raw:${id}`),
    bytes: "10",
  };
}

function review(id = "review1"): NativeRef {
  return {
    profile: "gateway.review/1",
    namespace: "local",
    object_id: id,
    commitment: null,
    raw_sha256: H(`review:${id}`),
    bytes: "10",
  };
}

async function paired(ports: MemoryCloudPorts) {
  const service = createCloudService(ports);
  const begin = await service.pairBegin({
    provider: "hosted",
    streams: ["receipts"],
    remote_ui: false,
  });
  const complete = await service.pairComplete({
    enrollment: begin.enrollment,
    binding: binding(),
    review: review(),
  });
  return { service, begin, complete };
}

describe("cloud.pair.begin", () => {
  it("returns enrollment id, AWAITING_PROVIDER, and a Crockford user code", async () => {
    const ports = createMemoryCloudPorts({ now: F.now });
    const service = createCloudService(ports);
    const res = await service.pairBegin({
      provider: "hosted",
      streams: ["receipts", "watch"],
      remote_ui: false,
    });
    expect(res.state).toBe("AWAITING_PROVIDER");
    expect(typeof res.enrollment).toBe("string");
    expect(isPairCode(res.user_code)).toBe(true);
    const stored = ports.enrollments.get(res.enrollment)!;
    expect("role" in stored).toBe(false); // enrollments carry no authority
    expect(stored.state).toBe("AWAITING_PROVIDER");
    expect(stored.expires_ms).toBe(F.now + 300_000);
  });

  it("requires a pinned provider — never enrolls a claimed URL", async () => {
    const ports = createMemoryCloudPorts({ providers: ["hosted"] });
    const service = createCloudService(ports);
    await expect(
      service.pairBegin({
        provider: "https://evil.example",
        streams: [],
        remote_ui: false,
      }),
    ).rejects.toMatchObject({ code: "NOT_FOUND", field: "provider" });
    await expect(
      service.pairBegin({
        provider: "hosted",
        streams: ["bogus" as never],
        remote_ui: false,
      }),
    ).rejects.toMatchObject({ code: "SCHEMA_INVALID", field: "streams" });
  });

  it("remote_ui needs the separately scoped gateway.ui.remote grant", async () => {
    const ports = createMemoryCloudPorts({ uiRemote: false });
    const service = createCloudService(ports);
    await expect(
      service.pairBegin({
        provider: "hosted",
        streams: [],
        remote_ui: true,
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN", field: "remote_ui" });
  });
});

describe("cloud.pair.complete", () => {
  it("pairs as viewer-only and re-checks the remote grant", async () => {
    const ports = createMemoryCloudPorts({ now: F.now, uiRemote: true });
    const service = createCloudService(ports);
    const begin = await service.pairBegin({
      provider: "hosted",
      streams: ["receipts"],
      remote_ui: true,
    });
    // Grant revoked between begin and complete must not carry through.
    ports.uiRemote = false;
    await expect(
      service.pairComplete({
        enrollment: begin.enrollment,
        binding: binding(),
        review: review(),
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN", field: "remote_ui" });
    expect(ports.enrollments.get(begin.enrollment)?.state).toBe(
      "AWAITING_PROVIDER",
    );

    ports.uiRemote = true;
    const done = await service.pairComplete({
      enrollment: begin.enrollment,
      binding: binding(),
      review: review(),
    });
    expect(done).toEqual({
      cloud: done.cloud,
      state: "PAIRED",
      remote_ui: true,
    });
    const cloud = ports.clouds.get(done.cloud)!;
    expect(cloud.role).toBe("viewer"); // never operator authority
    expect(cloud.remote_ui).toBe(true);
    expect(ports.enrollments.get(begin.enrollment)?.state).toBe("CONSUMED");

    // A consumed enrollment cannot complete twice.
    await expect(
      service.pairComplete({
        enrollment: begin.enrollment,
        binding: binding(),
        review: review(),
      }),
    ).rejects.toMatchObject({ code: "REVISION_CONFLICT" });
  });

  it("expires stale enrollments", async () => {
    const ports = createMemoryCloudPorts({ now: F.now });
    const service = createCloudService(ports);
    const begin = await service.pairBegin({
      provider: "hosted",
      streams: [],
      remote_ui: false,
    });
    ports.advance(300_001);
    await expect(
      service.pairComplete({
        enrollment: begin.enrollment,
        binding: binding(),
        review: review(),
      }),
    ).rejects.toMatchObject({ code: "PAIRING_EXPIRED" });
    expect(ports.enrollments.get(begin.enrollment)?.state).toBe("EXPIRED");
  });
});

describe("cloud.pair.revoke", () => {
  it("queues the remote notice when offline and revokes locally now", async () => {
    const ports = createMemoryCloudPorts(); // reachable=false by default
    const { service, complete } = await paired(ports);
    const res = await service.pairRevoke({ cloud: complete.cloud });
    expect(res).toEqual({
      cloud: complete.cloud,
      state: "REVOKED",
      remote_notice: "QUEUED",
    });
    expect(ports.clouds.get(complete.cloud)?.state).toBe("REVOKED");
    // Idempotent.
    const again = await service.pairRevoke({ cloud: complete.cloud });
    expect(again.remote_notice).toBe("QUEUED");
  });

  it("reports SENT when the provider notice is delivered", async () => {
    const ports = createMemoryCloudPorts({});
    ports.reachable = true;
    const { service, complete } = await paired(ports);
    const res = await service.pairRevoke({ cloud: complete.cloud });
    expect(res.remote_notice).toBe("SENT");
  });
});

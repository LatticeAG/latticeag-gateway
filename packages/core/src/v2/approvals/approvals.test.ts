/**
 * approval.* vectors — TV-GW-33 (deny-then-remote-approve CAS),
 * TV-GW-34 (expiry at equality), TV-GW-36 (viewer FORBIDDEN), plus
 * request shape, cancel, and paging (spec §3.2/§3.3).
 */
import { describe, expect, it } from "vitest";
import { H, J, now } from "@latticeag/testkit";
import type { NativeRef, ObjectRef } from "../protocol/refs.js";
import {
  createMemoryApprovalPorts,
  type MemoryApprovalPorts,
} from "./ports.js";
import {
  createApprovalRuntime,
  type ApprovalRuntime,
} from "./service.js";
import { actionCommitment, type ApprovalCaller } from "./approvals.js";

interface Ctx {
  ports: MemoryApprovalPorts;
  rt: ApprovalRuntime;
}

function setup(): Ctx {
  const ports = createMemoryApprovalPorts({ now });
  const rt = createApprovalRuntime(ports);
  return { ports, rt };
}

const ACTION: NativeRef = {
  profile: "latticeag.native/1",
  namespace: "products",
  object_id: "release1.install",
  commitment: "sha256:plan1",
  raw_sha256: H("native-action-1"),
  bytes: "128",
};

const NATIVE: ObjectRef = {
  digest: H("native-object-1"),
  bytes: "64",
  media: "application/json",
};

const REQUESTER: ApprovalCaller = {
  id: "peer1",
  role: "agent",
  reviewer: false,
};

const REVIEWER: ApprovalCaller = {
  id: "peer9",
  role: "agent",
  reviewer: true, // native-enrolled reviewer grant (server-side state)
};

const OPERATOR: ApprovalCaller = { id: "op1", role: "operator" };
const VIEWER: ApprovalCaller = { id: "ui1", role: "viewer" };

async function expectRpc(p: Promise<unknown>, code: string): Promise<void> {
  await expect(p).rejects.toMatchObject({ name: "RpcError", code });
}

async function request(ctx: Ctx, expires_ms = now + 60000) {
  return ctx.rt.service.request(
    {
      action: ACTION,
      target: "tool:release1.install",
      expires_ms,
      native: NATIVE,
    },
    REQUESTER,
  );
}

describe("approval.request — immutable action binding", () => {
  it("returns {approval, revision:'1', state:'PENDING', authority:'NONE'}", async () => {
    const ctx = setup();
    const out = await request(ctx);
    expect(out).toEqual({
      approval: "approval1",
      revision: "1",
      state: "PENDING",
      authority: "NONE",
    });
    const rec = ctx.ports.getApproval("approval1")!;
    expect(rec.state).toBe("PENDING");
    expect(rec.action).toEqual(ACTION);
    expect(rec.action_hash).toBe(actionCommitment(ACTION));
    expect(rec.native).toEqual(NATIVE);
    expect(rec.native_status).toBe("NOT_DISPATCHED");
    expect(rec.requester).toBe("peer1");
    expect(rec.target).toBe("tool:release1.install");
  });

  it("rejects malformed refs (closed objects, 64-hex digests)", async () => {
    const ctx = setup();
    await expectRpc(
      ctx.rt.service.request({
        action: { ...ACTION, extra: 1 } as unknown as NativeRef,
        target: "t",
        expires_ms: now + 60000,
        native: NATIVE,
      }),
      "SCHEMA_INVALID",
    );
    await expectRpc(
      ctx.rt.service.request({
        action: ACTION,
        target: "t",
        expires_ms: now + 60000,
        native: { ...NATIVE, digest: "zz" } as unknown as ObjectRef,
      }),
      "SCHEMA_INVALID",
    );
    expect(ctx.ports.listApprovals()).toHaveLength(0);
  });
});

describe("TV-GW-33 — deny commits first; remote approve same revision conflicts", () => {
  it("deny rev1→rev2; approve expecting rev1 → REVISION_CONFLICT, no resurrection", async () => {
    const ctx = setup();
    await request(ctx);

    const denied = await ctx.rt.service.decide(
      {
        approval: "approval1",
        expected_revision: "1",
        action: ACTION,
        decision: "deny",
        reason: "operator declined",
      },
      REVIEWER,
    );
    expect(denied).toEqual({
      approval: "approval1",
      revision: "2",
      state: "DENIED",
      native_status: "NOT_DISPATCHED",
    });

    // The remote approve also expected revision 1 — the committed deny wins.
    await expectRpc(
      ctx.rt.service.decide(
        {
          approval: "approval1",
          expected_revision: "1",
          action: ACTION,
          decision: "approve",
          reason: "remote ui click",
        },
        OPERATOR,
      ),
      "REVISION_CONFLICT",
    );

    // No resurrection: even a correct-revision approve on a decided row
    // is a terminal-state error, and the stored decision stays DENIED.
    await expectRpc(
      ctx.rt.service.decide(
        {
          approval: "approval1",
          expected_revision: "2",
          action: ACTION,
          decision: "approve",
          reason: "retry",
        },
        REVIEWER,
      ),
      "STATE_TRANSITION",
    );
    const rec = ctx.ports.getApproval("approval1")!;
    expect(rec.state).toBe("DENIED");
    expect(rec.revision).toBe("2");
    expect(rec.native_status).toBe("NOT_DISPATCHED");
  });

  it("approve on a fresh row commits APPROVED at revision 2", async () => {
    const ctx = setup();
    await request(ctx);
    const out = await ctx.rt.service.decide(
      {
        approval: "approval1",
        expected_revision: "1",
        action: ACTION,
        decision: "approve",
        reason: "ok",
      },
      OPERATOR,
    );
    expect(out).toEqual({
      approval: "approval1",
      revision: "2",
      state: "APPROVED",
      native_status: "NOT_DISPATCHED",
    });
    // A changed action commitment never satisfies the binding.
    await request(ctx);
    await expectRpc(
      ctx.rt.service.decide(
        {
          approval: "approval2",
          expected_revision: "1",
          action: { ...ACTION, object_id: "release2.install" },
          decision: "approve",
          reason: "ok",
        },
        OPERATOR,
      ),
      "REVISION_CONFLICT",
    );
    expect(ctx.ports.getApproval("approval2")!.state).toBe("PENDING");
  });
});

describe("TV-GW-34 — expiry at equality", () => {
  it("approve exactly at expires_ms → APPROVAL_EXPIRED", async () => {
    const ctx = setup();
    await request(ctx, now + 60000);
    ctx.ports.advance(60000);
    await expectRpc(
      ctx.rt.service.decide(
        {
          approval: "approval1",
          expected_revision: "1",
          action: ACTION,
          decision: "approve",
          reason: "too late",
        },
        REVIEWER,
      ),
      "APPROVAL_EXPIRED",
    );
    const rec = ctx.ports.getApproval("approval1")!;
    expect(rec.state).toBe("EXPIRED");
    expect(rec.native_status).toBe("NOT_DISPATCHED");
    // One millisecond earlier it would have decided.
    const ctx2 = setup();
    await request(ctx2, now + 60000);
    ctx2.ports.advance(59999);
    const ok = await ctx2.rt.service.decide(
      {
        approval: "approval1",
        expected_revision: "1",
        action: ACTION,
        decision: "approve",
        reason: "in time",
      },
      REVIEWER,
    );
    expect(ok.state).toBe("APPROVED");
  });
});

describe("TV-GW-36 — non-reviewers cannot decide", () => {
  it("viewer/agent-without-grant decide → FORBIDDEN", async () => {
    const ctx = setup();
    await request(ctx);
    await expectRpc(
      ctx.rt.service.decide(
        {
          approval: "approval1",
          expected_revision: "1",
          action: ACTION,
          decision: "approve",
          reason: "cloud viewer",
        },
        VIEWER,
      ),
      "FORBIDDEN",
    );
    // An ordinary agent without an enrolled reviewer grant is forbidden too.
    await expectRpc(
      ctx.rt.service.decide(
        {
          approval: "approval1",
          expected_revision: "1",
          action: ACTION,
          decision: "approve",
          reason: "claimed",
        },
        REQUESTER,
      ),
      "FORBIDDEN",
    );
    // The row is untouched — still PENDING at revision 1.
    const rec = ctx.ports.getApproval("approval1")!;
    expect(rec.state).toBe("PENDING");
    expect(rec.revision).toBe("1");
  });
});

describe("approval.cancel — requester-only, pending-only", () => {
  it("requester cancels: revision bumps, state CANCELLED", async () => {
    const ctx = setup();
    await request(ctx);
    const out = await ctx.rt.service.cancel(
      { approval: "approval1", expected_revision: "1" },
      REQUESTER,
    );
    expect(out).toEqual({
      approval: "approval1",
      revision: "2",
      state: "CANCELLED",
    });
    // Pending-only: a decided/cancelled row cannot be cancelled again.
    await expectRpc(
      ctx.rt.service.cancel(
        { approval: "approval1", expected_revision: "2" },
        REQUESTER,
      ),
      "STATE_TRANSITION",
    );
  });

  it("non-requester cancel → FORBIDDEN; viewer → FORBIDDEN", async () => {
    const ctx = setup();
    await request(ctx);
    await expectRpc(
      ctx.rt.service.cancel(
        { approval: "approval1", expected_revision: "1" },
        OPERATOR,
      ),
      "FORBIDDEN",
    );
    await expectRpc(
      ctx.rt.service.cancel(
        { approval: "approval1", expected_revision: "1" },
        VIEWER,
      ),
      "FORBIDDEN",
    );
    expect(ctx.ports.getApproval("approval1")!.state).toBe("PENDING");
  });
});

describe("approval.list/get — state filter and paging", () => {
  it("pages deterministically and filters by state", async () => {
    const ctx = setup();
    await request(ctx);
    await ctx.rt.service.request(
      {
        action: { ...ACTION, object_id: "release2.install" },
        target: "tool:release2.install",
        expires_ms: now + 60000,
        native: NATIVE,
      },
      REQUESTER,
    );
    await ctx.rt.service.decide(
      {
        approval: "approval2",
        expected_revision: "1",
        action: { ...ACTION, object_id: "release2.install" },
        decision: "approve",
        reason: "ok",
      },
      REVIEWER,
    );

    const pending = await ctx.rt.service.list({
      state: "PENDING",
      after: null,
      limit: 10,
    });
    expect(pending.items).toHaveLength(1);
    expect((pending.items[0] as { approval: string }).approval).toBe("approval1");

    const page1 = await ctx.rt.service.list({ after: null, limit: 1 });
    expect(page1.items).toHaveLength(1);
    expect(page1.next).toBe("approval1");
    const page2 = await ctx.rt.service.list({ after: page1.next, limit: 1 });
    expect(page2.items).toHaveLength(1);
    expect(page2.next).toBeNull();

    const got = await ctx.rt.service.get({ approval: "approval2" });
    expect(got).toMatchObject({
      approval: "approval2",
      revision: "2",
      state: "APPROVED",
      native_status: "NOT_DISPATCHED",
    });
    await expectRpc(
      ctx.rt.service.list({ after: "approvalX", limit: 10 }),
      "CURSOR_GONE",
    );
    await expectRpc(ctx.rt.service.get({ approval: "approvalX" }), "NOT_FOUND");
  });

  it("action_hash is H(J(action)) — the immutable binding commitment", () => {
    expect(actionCommitment(ACTION)).toBe(H(J(ACTION)));
  });
});

/**
 * Test support: createMemoryPorts() — in-memory catalog, trust store,
 * product registry (generation rows + active-pointer CAS), deterministic
 * clock option, journal/receipt recording, fault injection, and a
 * scriptable stub adapter for engine tests that must not spawn a real
 * child (health-failure candidates, drain counters, describe mismatches).
 */
import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";

import { RpcError } from "../protocol/errors.js";
import type { CatalogIndex } from "../protocol/catalog.js";
import type { Count, Json } from "../protocol/refs.js";
import type { Release } from "../protocol/product.js";

import type { AdapterChild } from "./adapter-client.js";
import { InjectedCrash } from "./engine.js";
import type {
  FetchedRelease,
  GenerationRow,
  JournalMutation,
  LifecyclePorts,
  PolicyView,
  SourceRef,
  TransitionReceipt,
} from "./ports.js";
import type { ReleaseTrust } from "./verify.js";

/** A scripted line-level adapter for adapter-client/engine tests. */
export interface StubScript {
  /** method → params → result, or an {error:{code,message}} shape. */
  readonly methods: Record<
    string,
    (params: Record<string, Json>) => Json | { error: { code: string; message: string } }
  >;
  /** Write raw garbage/oversized lines instead of a proper reply. */
  readonly rawReply?: (line: string, write: (s: string) => void) => void;
}

export class StubAdapterChild extends EventEmitter implements AdapterChild {
  readonly stdin: Writable;
  readonly stdout: PassThrough;
  readonly stderr: PassThrough;
  pid: number | undefined;
  killed = false;
  private line = "";
  private readonly script: StubScript;
  private static seq = 10_000;

  constructor(script: StubScript) {
    super();
    this.script = script;
    this.pid = StubAdapterChild.seq++;
    this.stdout = new PassThrough();
    this.stderr = new PassThrough();
    const out = this.stdout;
    const write = (s: string): void => {
      out.write(s);
    };
    this.stdin = new Writable({
      write: (chunk: Buffer, _enc, cb) => {
        this.line += chunk.toString("utf8");
        let idx: number;
        while ((idx = this.line.indexOf("\n")) >= 0) {
          const l = this.line.slice(0, idx);
          this.line = this.line.slice(idx + 1);
          if (this.script.rawReply) {
            this.script.rawReply(l, write);
            continue;
          }
          try {
            const req = JSON.parse(l) as {
              id: string;
              method: string;
              params?: Record<string, Json>;
            };
            const h = this.script.methods[req.method];
            if (h === undefined) {
              write(
                JSON.stringify({
                  v: 1,
                  id: req.id,
                  ok: false,
                  error: { code: "METHOD_UNKNOWN", retryable: false },
                }) + "\n",
              );
              continue;
            }
            const r = h(req.params ?? {});
            if (typeof r === "object" && r !== null && "error" in r) {
              write(
                JSON.stringify({ v: 1, id: req.id, ok: false, error: r.error }) + "\n",
              );
            } else {
              write(JSON.stringify({ v: 1, id: req.id, ok: true, result: r }) + "\n");
            }
          } catch {
            write(
              JSON.stringify({
                v: 1,
                id: "bad",
                ok: false,
                error: { code: "PROTOCOL_VIOLATION", retryable: false },
              }) + "\n",
            );
          }
        }
        cb();
      },
    });
  }

  kill(_signal?: string | number): boolean {
    if (this.killed) return false;
    this.killed = true;
    this.pid = undefined;
    queueMicrotask(() => this.emit("exit", 0, null));
    return true;
  }
}

export interface SpawnRecord {
  readonly cmd: readonly string[];
  readonly dir: string;
  readonly env: Record<string, string>;
  readonly child: AdapterChild;
}

export interface MemoryPortsOptions {
  readonly releases?: Record<string, { release: Release; archive: Uint8Array }>;
  readonly index?: CatalogIndex | null;
  readonly trust?: Partial<ReleaseTrust>;
  readonly platform?: { os: string; arch: string; node: string };
  readonly policy?: Partial<PolicyView>;
  readonly revisions?: { config: Count; catalog: Count; registry: Count };
  readonly spawnAdapter?: LifecyclePorts["spawnAdapter"];
  readonly stageRoot?: string;
  readonly dataRoot?: string;
  /** Deterministic clock: starts at startMs; sleep advances instantly. */
  readonly fakeClock?: { startMs: number };
  readonly probeGeneration?: (row: GenerationRow) => Promise<boolean>;
}

export interface MemoryPorts extends LifecyclePorts {
  readonly releases: Map<string, FetchedRelease>;
  readonly spawned: SpawnRecord[];
  readonly events: TransitionReceipt[];
  readonly journalLog: JournalMutation[];
  readonly rows: Map<string, Map<Count, GenerationRow>>;
  readonly stageRoot: string;
  readonly dataRoot: string;
  trust: ReleaseTrust;
  indexValue: CatalogIndex | null;
  policyView: PolicyView;
  /** Fault injection: throw InjectedCrash when a journal mutation arrives. */
  crashOn(type: JournalMutation["type"] | "*", detail?: string): void;
  clearCrash(): void;
  /** Inject a pre-existing generation row (e.g. a retained version). */
  putGeneration(row: GenerationRow): void;
  /** Add a release to the catalog. */
  putRelease(release: Release, archive: Uint8Array): void;
  /** Deterministic clock helpers when fakeClock was requested. */
  readonly advance: (ms: number) => void;
  cleanup(): void;
}

export function createMemoryPorts(opts: MemoryPortsOptions = {}): MemoryPorts {
  const stageRoot = opts.stageRoot ?? mkdtempSync(join(tmpdir(), "gw-stage-"));
  const dataRoot = opts.dataRoot ?? mkdtempSync(join(tmpdir(), "gw-data-"));
  const releases = new Map<string, FetchedRelease>();
  const spawned: SpawnRecord[] = [];
  const events: TransitionReceipt[] = [];
  const journalLog: JournalMutation[] = [];
  const rows = new Map<string, Map<Count, GenerationRow>>();
  const genSeq = new Map<string, number>();
  let crashTypes: { type: JournalMutation["type"] | "*"; detail?: string }[] = [];
  let nowMs = opts.fakeClock?.startMs ?? Date.now();
  const realClock = opts.fakeClock === undefined;

  const registry: MemoryPorts["productRegistry"] = {
    generations: (slug) =>
      [...(rows.get(slug)?.values() ?? [])].sort((a, b) =>
        Number(BigInt(a.generation) - BigInt(b.generation)),
      ),
    all: () => [...rows.values()].flatMap((m) => [...m.values()]),
    get: (slug, generation) => rows.get(slug)?.get(generation),
    create: (row) => {
      let m = rows.get(row.slug);
      if (!m) rows.set(row.slug, (m = new Map()));
      m.set(row.generation, row);
      return row;
    },
    update: (slug, generation, patch) => {
      const row = rows.get(slug)?.get(generation);
      if (row) Object.assign(row, patch);
    },
    active: (slug) =>
      [...(rows.get(slug)?.values() ?? [])].find((r) => r.active),
    casActive: (slug, expected, next) => {
      const m = rows.get(slug);
      const cur = [...(m?.values() ?? [])].find((r) => r.active) ?? null;
      if ((cur?.generation ?? null) !== expected) return false;
      if (cur) cur.active = false;
      if (next !== null) {
        const nxt = m?.get(next);
        if (!nxt) return false;
        nxt.active = true;
      }
      return true;
    },
    nextGeneration: (slug) => {
      const n = (genSeq.get(slug) ?? 0) + 1;
      genSeq.set(slug, n);
      return String(n) as Count;
    },
    revision: () => "1" as Count,
  };

  const defaultSpawn: LifecyclePorts["spawnAdapter"] = (cmd, dir, env) => {
    return spawn(cmd[0]!, [...cmd.slice(1)], {
      cwd: dir,
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    }) as unknown as AdapterChild;
  };

  const ports: MemoryPorts = {
    catalog: {
      fetch: (sref: SourceRef) => {
        const f = releases.get(`${sref.slug}@${sref.version}`);
        if (!f) {
          return Promise.reject(
            new RpcError("NOT_FOUND", `catalog has no ${sref.slug}@${sref.version}`),
          );
        }
        return Promise.resolve(f);
      },
      index: () => Promise.resolve(ports.indexValue),
      versions: (slug) =>
        Promise.resolve(
          [...releases.keys()]
            .filter((k) => k.startsWith(`${slug}@`))
            .map((k) => k.slice(slug.length + 1)),
        ),
    },
    trustStore: () => ports.trust,
    productRegistry: registry,
    spawnAdapter: (cmd, dir, env) => {
      const fn = opts.spawnAdapter ?? defaultSpawn;
      const r = fn(cmd, dir, env);
      if (r instanceof Promise) {
        return r.then((child) => {
          spawned.push({ cmd, dir, env, child });
          return child;
        });
      }
      spawned.push({ cmd, dir, env, child: r });
      return r;
    },
    clock: {
      now: () => (realClock ? Date.now() : nowMs),
      sleep: (ms) => {
        if (realClock) return new Promise((r) => setTimeout(r, ms));
        nowMs += ms;
        return Promise.resolve();
      },
    },
    journalMutation: (m) => {
      journalLog.push(m);
      const hit = crashTypes.find((c) => c.type === "*" || c.type === m.type);
      if (hit) {
        crashTypes = crashTypes.filter((c) => c !== hit);
        throw new InjectedCrash(`injected crash at ${m.type}`);
      }
    },
    receiptSink: (e) => {
      events.push(e);
    },
    paths: {
      stageDir: (slug, gen) => join(stageRoot, `${slug}@${gen}`),
      dataDir: (slug, gen) => join(dataRoot, `${slug}@${gen}`),
      removeStage: (dir) => {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          /* retained on failure */
        }
      },
    },
    platform: () =>
      opts.platform ?? {
        os: process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux",
        arch: process.arch === "arm64" ? "arm64" : "x64",
        node: `v${process.versions.node}`,
      },
    policy: () => ports.policyView,
    revisions: () => opts.revisions ?? { config: "1", catalog: "1", registry: "1" },
    probeGeneration: opts.probeGeneration ?? (() => Promise.resolve(true)),

    releases,
    spawned,
    events,
    journalLog,
    rows,
    stageRoot,
    dataRoot,
    trust: {
      releaseKeys: new Set<string>(),
      builders: new Set<string>(),
      revocations: new Set<string>(),
      ...opts.trust,
    },
    indexValue: opts.index ?? null,
    policyView: {
      strict: opts.policy?.strict ?? false,
      allowlist: opts.policy?.allowlist ?? [],
      sandboxes: opts.policy?.sandboxes ?? ["linux-ns", "oci", "wasi"],
    },
    crashOn: (type, detail) => {
      crashTypes.push({ type, detail });
    },
    clearCrash: () => {
      crashTypes = [];
    },
    putGeneration: (row) => {
      registry.create(row);
    },
    putRelease: (release, archive) => {
      // Derive the locator from the manifest blob's slug/version.
      const parsed = JSON.parse(
        Buffer.from(release.manifest.content, "base64url").toString("utf8"),
      ) as { slug?: string; version?: string };
      if (typeof parsed.slug !== "string" || typeof parsed.version !== "string") {
        throw new RpcError("SCHEMA_INVALID", "release manifest blob lacks slug/version");
      }
      releases.set(`${parsed.slug}@${parsed.version}`, { release, archive });
    },
    advance: (ms) => {
      nowMs += ms;
    },
    cleanup: () => {
      rmSync(stageRoot, { recursive: true, force: true });
      rmSync(dataRoot, { recursive: true, force: true });
    },
  };
  return ports;
}

/** A fresh retained-generation row for tests (e.g. a rollback target). */
export function retainedRow(
  slug: string,
  version: string,
  generation: Count,
  manifestDigest: string,
  archiveDigest: string,
  patch: Partial<GenerationRow> = {},
): GenerationRow {
  return {
    slug,
    version,
    generation,
    state: "STOPPED_RETAINED",
    active: false,
    manifest_digest: manifestDigest as GenerationRow["manifest_digest"],
    archive_digest: archiveDigest,
    staged_dir: null,
    data_dir: null,
    pid: null,
    dependencies: [],
    activation_indexed: true,
    projected: true,
    snapshot_verified: false,
    irreversible_data: false,
    capabilities_withdrawn: false,
    starts: [],
    ...patch,
  };
}

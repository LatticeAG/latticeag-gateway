import { homedir } from "node:os";
import { join } from "node:path";
import { ensureDir } from "./util.js";

/**
 * Resolved state-root layout per spec §8.3. Every directory listed here is
 * created 0700 and every file written 0600 by the storage layer.
 */
export interface StateLayout {
  /** `<state root>` itself. */
  root: string;
  /** `runtime/` — lock metadata, actual endpoints, boot/session identity. */
  runtimeDir: string;
  /** `journal/` — durable commit markers. */
  journalDir: string;
  /** `journal/commits.jsonl`. */
  commitsPath: string;
  /** `journal/quarantine/` — preserved damaged/orphan evidence. */
  quarantineDir: string;
  /** `bus/` — JSONL lanes root. */
  busDir: string;
  /** `bus/legacy/` — legacy event lane. */
  legacyLaneDir: string;
  /** `bus/proof/` — proof partition lanes root. */
  proofBusDir: string;
  /** `objects/sha256/` — content-addressed immutable objects. */
  objectsDir: string;
  packagesDir: string;
  productsDir: string;
  catalogDir: string;
  trustDir: string;
  outboxDir: string;
  fallbackDir: string;
  keysDir: string;
  logsDir: string;
  backupsDir: string;
  serviceDir: string;
  /** `registry.sqlite` — derived WAL index. */
  registryPath: string;
  /** `contracts.lock` — signed native/artifact/source pins. */
  contractsPath: string;
}

/**
 * Project state root: `<config-dir>/.latticeag` per §8.3.
 * `instance` is accepted for API symmetry with `osStateRoot`; project state
 * is per-config-file and does not nest per instance.
 */
export function stateRoot(configDir: string, _instance?: string): string {
  return join(configDir, ".latticeag");
}

/**
 * OS-user service state root per §8.3:
 * `$XDG_STATE_HOME/latticeag/<instance>` (Linux/other),
 * `~/Library/Application Support/LatticeAG/Gateway/<instance>` (macOS),
 * `%LOCALAPPDATA%\LatticeAG\Gateway\<instance>` (Windows).
 */
export function osStateRoot(instance: string): string {
  if (process.platform === "darwin") {
    return join(
      homedir(),
      "Library",
      "Application Support",
      "LatticeAG",
      "Gateway",
      instance,
    );
  }
  if (process.platform === "win32") {
    const base = process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local");
    return join(base, "LatticeAG", "Gateway", instance);
  }
  const base =
    process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state");
  return join(base, "latticeag", instance);
}

/** Resolve the full layout for an existing or prospective state root. */
export function layout(root: string): StateLayout {
  const journalDir = join(root, "journal");
  const busDir = join(root, "bus");
  return {
    root,
    runtimeDir: join(root, "runtime"),
    journalDir,
    commitsPath: join(journalDir, "commits.jsonl"),
    quarantineDir: join(journalDir, "quarantine"),
    busDir,
    legacyLaneDir: join(busDir, "legacy"),
    proofBusDir: join(busDir, "proof"),
    objectsDir: join(root, "objects", "sha256"),
    packagesDir: join(root, "packages"),
    productsDir: join(root, "products"),
    catalogDir: join(root, "catalog"),
    trustDir: join(root, "trust"),
    outboxDir: join(root, "outbox"),
    fallbackDir: join(root, "fallback"),
    keysDir: join(root, "keys"),
    logsDir: join(root, "logs"),
    backupsDir: join(root, "backups"),
    serviceDir: join(root, "service"),
    registryPath: join(root, "registry.sqlite"),
    contractsPath: join(root, "contracts.lock"),
  };
}

/** All directories that must exist with mode 0700, in stable order. */
export function layoutDirs(l: StateLayout): string[] {
  return [
    l.root,
    l.runtimeDir,
    l.journalDir,
    l.quarantineDir,
    l.busDir,
    l.legacyLaneDir,
    l.proofBusDir,
    l.objectsDir,
    l.packagesDir,
    l.productsDir,
    l.catalogDir,
    l.trustDir,
    l.outboxDir,
    l.fallbackDir,
    l.keysDir,
    l.logsDir,
    l.backupsDir,
    l.serviceDir,
  ];
}

/** Create the state root tree with 0700 directories. Idempotent. */
export async function ensureLayout(root: string): Promise<StateLayout> {
  const l = layout(root);
  for (const dir of layoutDirs(l)) {
    await ensureDir(dir);
  }
  return l;
}

import { latticeagConfigV2Schema } from "./schema-v2.js";

export interface ConfigV2Issue {
  code: string;
  path: string;
  message: string;
}

export interface ValidateConfigV2Options {
  /**
   * Whether the operator currently holds an explicit cloud UI grant.
   * `gateway.ui.remote=true` is rejected without it — direct local file
   * edits cannot mint that grant.
   */
  hasCloudUiGrant?: boolean;
}

export interface ConfigV2ValidationResult {
  valid: boolean;
  errors: ConfigV2Issue[];
}

const SEMVER = new RegExp(
  "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)" +
    "(?:-(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)" +
    "(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?" +
    "(?:\\+[0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*)?$",
);

const HASH64 = /^[0-9a-f]{64}$/;

const DISK_BYTES_MIN = 67108864n; // 64 MiB
const DISK_BYTES_MAX = (1n << 63n) - 1n; // 2^63 - 1

/**
 * Semantic validation of a v2 config document beyond the structural schema
 * (spec §8.1/§8.2): loopback-only binds, cloud-UI grant for remote mode,
 * disk_bytes native bounds, trusted HTTPS catalog origins, unique pin slugs,
 * exact SemVer pin versions, and 64-hex product manifests.
 */
export function validateConfigV2Semantics(
  doc: unknown,
  opts: ValidateConfigV2Options = {},
): ConfigV2ValidationResult {
  const parsed = latticeagConfigV2Schema.safeParse(doc);
  if (!parsed.success) {
    return {
      valid: false,
      errors: parsed.error.issues.map((issue) => ({
        code: "SCHEMA_INVALID",
        path: issue.path.length > 0 ? issue.path.join(".") : "(root)",
        message: issue.message,
      })),
    };
  }

  const cfg = parsed.data;
  const errors: ConfigV2Issue[] = [];
  const issue = (code: string, issuePath: string, message: string): void => {
    errors.push({ code, path: issuePath, message });
  };

  // All TCP binds remain loopback, even with remote=true (TV-GW-39).
  if (cfg.gateway.ui.bind !== "127.0.0.1") {
    issue(
      "SCHEMA_INVALID",
      "gateway.ui.bind",
      `ui.bind must be "127.0.0.1", got ${JSON.stringify(cfg.gateway.ui.bind)}`,
    );
  }

  // ui.remote requires a current explicit cloud UI grant, not merely
  // sync.enabled; local file edits cannot mint that grant.
  if (cfg.gateway.ui.remote === true && opts.hasCloudUiGrant !== true) {
    issue(
      "GRANT_REQUIRED",
      "gateway.ui.remote",
      "ui.remote requires a current explicit cloud UI grant",
    );
  }

  // disk_bytes must parse and land in [64 MiB, 2^63 - 1].
  let diskBytes: bigint | null = null;
  try {
    diskBytes = BigInt(cfg.storage.disk_bytes);
  } catch {
    diskBytes = null;
  }
  if (
    diskBytes === null ||
    diskBytes < DISK_BYTES_MIN ||
    diskBytes > DISK_BYTES_MAX
  ) {
    issue(
      "VALUE_RANGE",
      "storage.disk_bytes",
      `disk_bytes must be between ${DISK_BYTES_MIN} and ${DISK_BYTES_MAX}`,
    );
  }

  // storage.root must be a non-empty canonical path.
  if (cfg.storage.root.length === 0) {
    issue("SCHEMA_INVALID", "storage.root", "storage.root must be non-empty");
  }

  // Trusted HTTPS catalog origins only; a null source selects the bundled
  // signed index.
  if (cfg.catalog.source !== null) {
    let url: URL | null = null;
    try {
      url = new URL(cfg.catalog.source);
    } catch {
      url = null;
    }
    if (url === null || url.protocol !== "https:") {
      issue(
        "ORIGIN_UNTRUSTED",
        "catalog.source",
        "catalog.source must be an HTTPS origin or null",
      );
    }
  }

  // One pin per slug; exact SemVer versions.
  const seenSlugs = new Set<string>();
  cfg.catalog.pins.forEach((pin, index) => {
    if (seenSlugs.has(pin.slug)) {
      issue(
        "PIN_DUPLICATE",
        `catalog.pins.${index}.slug`,
        `duplicate catalog pin slug ${JSON.stringify(pin.slug)}`,
      );
    }
    seenSlugs.add(pin.slug);
    if (!SEMVER.test(pin.version)) {
      issue(
        "SEMVER_INVALID",
        `catalog.pins.${index}.version`,
        `catalog pin version ${JSON.stringify(pin.version)} is not exact SemVer`,
      );
    }
  });

  // Product instance manifests are 64-hex digests.
  for (const [slug, instance] of Object.entries(cfg.products.instances)) {
    if (!HASH64.test(instance.manifest)) {
      issue(
        "SCHEMA_INVALID",
        `products.instances.${slug}.manifest`,
        "product instance manifest must be a 64-hex sha256 digest",
      );
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Gateway v2 crypto / canonical-evidence primitives (spec §2.1, §4.2,
 * §4.3, §5.1, §13.1). Pure functions, node:crypto only, zero deps.
 */
export * from "./errors.js";
export * from "./canonical.js";
export * from "./hash.js";
export * from "./ids.js";
export * from "./ed25519.js";
export * from "./proof.js";
export * from "./sunlight.js";
export * from "./pairing.js";

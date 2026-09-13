/**
 * Gateway v2 barrel — exposes the protocol contract layer and the
 * crypto/canonical-evidence primitives as namespaces so the root index can
 * publish `v2` without symbol collisions between the two trees.
 */
export * as protocol from "./protocol/index.js";
export * as crypto from "./crypto/index.js";

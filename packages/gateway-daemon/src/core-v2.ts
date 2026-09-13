/**
 * Single point of contact with the Gateway v2 protocol/crypto contract in
 * `@latticeag/core`.
 *
 * The core package's `exports` map publishes only its top-level index; the
 * v2 surface (spec §3/§4 contract: envelope, error registry, RPC registry,
 * services interfaces, canonical JSON, Ed25519 helpers, Proof sealing,
 * pairing domains, id/cursor helpers) is compiled to `dist/v2/` but has no
 * bare-specifier export yet. To code against the contract without modifying
 * another package, we deep-import the built files through a RELATIVE path.
 *
 * Layout invariant that makes this safe: the specifier resolves identically
 * from TypeScript source and compiled output because `src/` and `dist/` sit
 * at the same depth inside this package —
 *   src/<file>.ts      → ../../core/dist/v2/…  = packages/core/dist/v2/…
 *   dist/<file>.js     → ../../core/dist/v2/…  = packages/core/dist/v2/…
 * TypeScript resolves the `.js` specifier to the adjacent `.d.ts` (a
 * declaration file, so `rootDir` is unaffected); Node resolves it to the
 * real compiled file at runtime. pnpm builds `core` before this package.
 *
 * When `@latticeag/core` grows a `./v2/*` exports entry this file should be
 * reduced to `export * from "@latticeag/core/v2"` (or equivalent).
 */
export * from "../../core/dist/v2/protocol/index.js";
export * from "../../core/dist/v2/crypto/index.js";

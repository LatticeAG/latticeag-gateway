/**
 * Gateway v2 agent-peer subsystem (spec §4): pairing ceremony, grant/token
 * service, per-request key proofs, scope admission, peer registry,
 * connector families, and the agent.* service facade.
 */
export * from "./ports.js";
export * from "./pairs.js";
export * from "./tokens.js";
export * from "./proofs.js";
export * from "./scopes.js";
export * from "./registry.js";
export * from "./families.js";
export * from "./service.js";

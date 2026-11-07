export const ENV_EXAMPLE = `export OPENAI_API_KEY=
export ANTHROPIC_API_KEY=
export AXION_READ_TOKEN=
export AXION_WEBHOOK_SECRET=
export AXION_WEBHOOK_ALLOW_UNSIGNED=true
export LEXVERDICT_URL=http://127.0.0.1:8789
export VEKINBOX_URL=http://127.0.0.1:3001/v1
export VEKINBOX_API_KEY=
export VEKINBOX_WORKSPACE_ID=
export VEKINBOX_AGENT_ID=
export VEKINBOX_AUTO_APPROVE=
export VEKINBOX_WEBHOOK_SECRET=
export VEKINBOX_FIXTURE_MODE=
export LEXGATEWAY_URL=http://127.0.0.1:8788
export LEXGATEWAY_TOKEN=
export POLYMESH_API_KEY=
export POLYMESH_GATEWAY_URL=
export POLYMESH_MESH_ID=
export LATTICEAG_GOAL="Write production config.yaml with env: production and replicas: 3"
export LATTICEAG_ALLOW_UNREDACTED=
export LATTICEAG_CONFIG=
export LATTICEAG_INGEST_EXPOSE=
export LATTICEAG_DOCTOR_ALLOW_MISSING_ADAPTERS=
export LATTICEAG_ALLOW_MISSING_DIFF=
`;

export const AGENT_STUB = `// latticeag attach target. Replace with your agent.
// The CLI does not import this file. You run it via:
//   latticeag run --attach openai-completions --cmd "npx tsx src/agent.ts"
console.log("replace this stub");
`;

export const GITIGNORE_RULES = [
  "node_modules/",
  "dist/",
  ".latticeag/events.jsonl",
  ".latticeag/events.jsonl.*",
  ".latticeag/sessions/",
  ".latticeag/sync-outbox.jsonl",
  ".env",
  ".env.*",
  "!.env.example",
  "*SPEC*.md",
  "*.pem",
];

/**
 * Vite singlefile build for the loopback workbench (spec §7).
 *
 * Output contract: `dist/index.html` is the ONLY runtime asset — all
 * script/style bytes are inlined so the bridge serves exactly one file.
 * `dist/manifest.json` lists SHA-256 digests of every inline script/style
 * block plus the whole document; the daemon's release CSP may then extend
 * `script-src 'self'`/`style-src 'self'` with `sha256-…` sources for those
 * exact bytes (spec §7.2) — never `unsafe-inline`/`unsafe-eval`.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, type Plugin } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";

const INLINE_BLOCK = {
  script: /<script[^>]*>([\s\S]*?)<\/script>/gi,
  style: /<style[^>]*>([\s\S]*?)<\/style>/gi,
} as const;

function sha256B64(bytes: string): string {
  return createHash("sha256").update(bytes, "utf8").digest("base64");
}

/** Emit dist/manifest.json with sha256 CSP sources for the inlined blocks. */
function cspManifest(): Plugin {
  return {
    name: "latticeag-csp-manifest",
    apply: "build",
    closeBundle() {
      const outDir = join(__dirname, "dist");
      let html: string;
      try {
        html = readFileSync(join(outDir, "index.html"), "utf8");
      } catch {
        return;
      }
      const collect = (re: RegExp): string[] => {
        const hashes: string[] = [];
        for (const m of html.matchAll(re)) {
          const body = m[1] ?? "";
          if (body.length > 0) hashes.push(`sha256-${sha256B64(body)}`);
        }
        return hashes;
      };
      const manifest = {
        v: 1,
        file: "index.html",
        sha256: sha256B64(html),
        "script-src": collect(new RegExp(INLINE_BLOCK.script.source, "gi")),
        "style-src": collect(new RegExp(INLINE_BLOCK.style.source, "gi")),
      };
      writeFileSync(
        join(outDir, "manifest.json"),
        `${JSON.stringify(manifest, null, 2)}\n`,
      );
    },
  };
}

export default defineConfig({
  plugins: [viteSingleFile(), cspManifest()],
  build: {
    target: "es2022",
    outDir: "dist",
    assetsInlineLimit: 100 * 1024 * 1024,
    cssCodeSplit: false,
    modulePreload: false,
    sourcemap: false,
    minify: "esbuild",
    rollupOptions: {
      output: { inlineDynamicImports: true },
    },
  },
  server: {
    // Dev-only convenience: same-origin proxy to a running daemon.
    proxy: {
      "/v2": "http://127.0.0.1:9848",
      "/healthz": "http://127.0.0.1:9848",
      "/readyz": "http://127.0.0.1:9848",
    },
  },
});

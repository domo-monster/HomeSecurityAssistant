// Minimal static server for the browser tests (no dependencies).
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const repo = fileURLToPath(new URL("../../", import.meta.url));
const routes = [
  ["/panel/", join(repo, "custom_components/homesec/frontend/")],
  ["/api/homesec/frontend/", join(repo, "custom_components/homesec/frontend/")],
  ["/tests/", join(repo, "frontend/tests/")],
];
const types = { ".js": "text/javascript", ".mjs": "text/javascript", ".html": "text/html", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png" };
const port = Number(process.env.PORT || 4173);

createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  for (const [prefix, dir] of routes) {
    if (!path.startsWith(prefix)) continue;
    const file = normalize(join(dir, path.slice(prefix.length)));
    if (!file.startsWith(dir)) break;
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": types[extname(file)] || "application/octet-stream", "cache-control": "no-store" });
      res.end(body);
      return;
    } catch {
      break;
    }
  }
  res.writeHead(404).end("not found");
}).listen(port, "127.0.0.1", () => console.log(`test server on http://127.0.0.1:${port}`));

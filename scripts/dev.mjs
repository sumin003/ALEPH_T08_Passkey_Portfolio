import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import privateInfo from "../api/private-info.js";
import passkeys from "../api/passkeys.js";

const root = path.resolve(fileURLToPath(new URL("../dist/", import.meta.url)));
const types = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".png": "image/png" };

// Local verification server: only serves the public build, never the repo root.
export function createDevServer() {
    return createServer(async (req, res) => {
        try {
            const url = new URL(req.url, "http://localhost");
            if (["/api/private-info", "/api/passkeys"].includes(url.pathname)) {
                const handler = url.pathname === "/api/passkeys" ? passkeys : privateInfo;
                const body = req.method === "GET" || req.method === "HEAD" ? undefined : req;
                const response = await handler.fetch(new Request(url, {
                    method: req.method,
                    headers: req.headers, body, ...(body ? { duplex: "half" } : {})
                }));
                res.writeHead(response.status, Object.fromEntries(response.headers));
                res.end(Buffer.from(await response.arrayBuffer()));
                return;
            }
            if (!["GET", "HEAD"].includes(req.method)) {
                res.writeHead(405, { Allow: "GET, HEAD" });
                res.end();
                return;
            }
            const pathname = decodeURIComponent(url.pathname);
            const file = path.resolve(root, "." + (pathname === "/" ? "/index.html" : pathname));
            if (!file.startsWith(root + path.sep)) {
                res.writeHead(404); res.end(); return;
            }
            const body = await readFile(file);
            res.writeHead(200, { "Content-Type": types[path.extname(file)] || "application/octet-stream", "X-Content-Type-Options": "nosniff" });
            res.end(req.method === "HEAD" ? undefined : body);
        } catch {
            res.writeHead(404); res.end();
        }
    });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    await import("./build.mjs");
    const port = Number(process.env.PORT || 3000);
    createDevServer().listen(port, "127.0.0.1", () => console.log(`http://127.0.0.1:${port}`));
}

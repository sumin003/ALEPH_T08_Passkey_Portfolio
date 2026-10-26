import { cp, mkdir, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = path.join(root, "dist");
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });

// Only these public files are deployed as static assets.
// Never copy server/, tests/, docs/, configuration or environment files.
for (const name of ["index.html", "style.css", "script.js"]) {
    await cp(path.join(root, name), path.join(output, name));
}
if (existsSync(path.join(root, "images"))) {
    await cp(path.join(root, "images"), path.join(output, "images"), {
        recursive: true,
        dereference: false
    });
}
console.log("Public build created in dist/ (server records excluded).");

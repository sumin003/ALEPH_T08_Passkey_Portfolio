import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { once } from "node:events";
import { privateItems } from "../server/private-items.mjs";
import { createDevServer } from "../scripts/dev.mjs";
import "../scripts/build.mjs";

test("server draft contains the three agreed headings with empty bodies", () => {
    assert.deepEqual(privateItems.map(item => item.title), [
        "준비 중인 프로젝트 메모", "개인 목표와 진행 상황", "스스로 쓰는 회고"
    ]);
    assert.ok(privateItems.every(item => item.content === ""));
});

test("private drafts and server files are absent from public output", async () => {
    const names = await readdir(new URL("../dist/", import.meta.url));
    assert.ok(names.every(name => ["index.html", "style.css", "script.js", "passkeys.js", "images"].includes(name)));
    for (const name of ["index.html", "style.css", "script.js", "passkeys.js"]) {
        const source = await readFile(new URL(`../dist/${name}`, import.meta.url), "utf8");
        for (const item of privateItems) {
            assert.ok(!source.includes(item.title), `${name} must not contain ${item.id}`);
        }
    }
});

test("HTTP requests cannot bypass the private boundary", async (t) => {
    const server = createDevServer();
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    t.after(() => new Promise(resolve => server.close(resolve)));
    const base = `http://127.0.0.1:${server.address().port}`;

    const page = await fetch(base);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.ok(html.includes("공개정보"));
    assert.ok(html.includes("비공개 · 잠김"));
    assert.ok(html.includes("sumin0516a@naver.com"));

    for (const input of [
        { label: "direct", path: "/api/private-info" },
        { label: "query", path: "/api/private-info?loggedIn=true&userId=owner" },
        { label: "forged-cookie", path: "/api/private-info", headers: { Cookie: "session=fake; loggedIn=true" } },
        { label: "forged-bearer", path: "/api/private-info", headers: { Authorization: "Bearer fake" } },
        { label: "post", path: "/api/private-info", method: "POST", body: '{"authenticated":true}' }
    ]) {
        const { label, path, ...options } = input;
        const response = await fetch(base + path, options);
        assert.equal(response.status, 401, label);
        assert.match(response.headers.get("cache-control"), /no-store/);
        const body = await response.json();
        assert.equal(body.error, "AUTH_REQUIRED");
        assert.ok(!("items" in body));
        for (const item of privateItems) assert.ok(!JSON.stringify(body).includes(item.title));
    }

    const head = await fetch(base + "/api/private-info", { method: "HEAD" });
    assert.equal(head.status, 401);
    assert.equal(await head.text(), "");

    for (const route of ["/server/private-items.mjs", "/docs/CARD1.md", "/package.json", "/.env", "/api/private-info.js"]) {
        assert.equal((await fetch(base + route)).status, 404, route);
    }
});

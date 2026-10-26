import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createRegistrationHandler, createDatabase } from "../server/registration.mjs";

const origin = "https://alepht08passkeyportfolio.vercel.app";

function fixture() {
    const challenges = new Map(); const users = new Map(); const saved = [];
    let verifyArgs;
    const db = {
        findEnrollment: async hash => users.get(hash) || null,
        list: async id => saved.filter(row => row.user_id === id).map(row => ({ name: row.name, created_at: row.created_at, storage_label: row.storage_label })),
        create: async row => challenges.set(row.id, { ...row }),
        findChallenge: async (id, hash) => {
            const row = challenges.get(id); return row?.binding_hash === hash ? row : null;
        },
        cancel: async (id, hash) => {
            const row = challenges.get(id); if (row?.binding_hash === hash && !row.used_at) challenges.delete(id);
        },
        finish: async data => {
            const row = challenges.get(data.p_challenge_id);
            assert.ok(row && !row.used_at && row.binding_hash === data.p_binding_hash);
            row.used_at = new Date().toISOString();
            users.set(row.binding_hash, { id: row.candidate_user_id });
            saved.push({ user_id: row.candidate_user_id, name: row.passkey_name, storage_label: row.storage_label, public_key: data.p_public_key, created_at: new Date().toISOString() });
        }
    };
    // These mocks test application control flow, NOT WebAuthn cryptographic verification.
    const lib = {
        generateRegistrationOptions: async input => ({
            challenge: randomBytes(32).toString("base64url"),
            user: { id: Buffer.from(input.userID).toString("base64url"), name: input.userName },
            rp: { id: input.rpID }, authenticatorSelection: input.authenticatorSelection
        }),
        verifyRegistrationResponse: async input => {
            verifyArgs = input;
            if (input.response?.invalid) throw Error("DO_NOT_LEAK_INTERNAL_ERROR");
            return { verified: true, registrationInfo: {
                credential: { id: "test-public-credential", publicKey: new Uint8Array([1, 2, 3]), counter: 0, transports: ["internal"] },
                credentialDeviceType: "multiDevice", credentialBackedUp: true
            } };
        }
    };
    const handle = createRegistrationHandler({ database: () => db, library: async () => lib,
        configuration: () => ({ origin, rpID: new URL(origin).hostname }) });
    async function request(action, body, cookie) {
        const headers = { Origin: origin };
        if (body !== undefined) headers["Content-Type"] = "application/json";
        if (cookie) headers.Cookie = cookie;
        return handle(new Request(`${origin}/api/passkeys?action=${action}`, {
            method: body === undefined ? "GET" : "POST", headers,
            body: body === undefined ? undefined : JSON.stringify(body)
        }));
    }
    async function start() {
        const response = await request("options", { name: "테스트 노트북", storage: "테스트 기기" });
        assert.equal(response.status, 200);
        return { data: await response.json(), cookie: response.headers.get("set-cookie").split(";")[0], headers: response.headers };
    }
    return { handle, request, start, challenges, users, saved, get verifyArgs() { return verifyArgs; } };
}

test("registration questions differ, are server-stored and have secure binding cookies", async () => {
    const f = fixture(); const a = await f.start(); const b = await f.start();
    assert.notEqual(a.data.options.challenge, b.data.options.challenge);
    assert.equal(f.challenges.get(a.data.challengeId).challenge, a.data.options.challenge);
    assert.match(a.headers.get("set-cookie"), /HttpOnly; Secure; SameSite=Strict/);
    assert.equal(f.users.size, 0); assert.equal(f.saved.length, 0);
});

test("only validated registration is saved; question cannot be replayed (verifier mocked)", async () => {
    const f = fixture(); const { data, cookie } = await f.start();
    const result = await f.request("verify", { challengeId: data.challengeId, credential: {} }, cookie);
    assert.equal(result.status, 200);
    assert.equal((await result.json()).privateAccessGranted, false);
    assert.equal(f.saved.length, 1);
    assert.equal(f.verifyArgs.expectedChallenge, data.options.challenge);
    assert.equal(f.verifyArgs.expectedOrigin, origin);
    assert.equal(f.verifyArgs.requireUserVerification, true);
    assert.equal((await f.request("verify", { challengeId: data.challengeId, credential: {} }, cookie)).status, 409);
    const list = await f.request("list", undefined, cookie);
    const records = await list.json();
    assert.equal(records.passkeys.length, 1);
    assert.equal(records.passkeys[0].name, "테스트 노트북");
    assert.ok(!JSON.stringify(records).includes("public_key"));
    assert.equal((await f.request("options", { name: "extra", storage: "device" }, cookie)).status, 409);
});

test("cancellation deletes pending question and creates no user or credential", async () => {
    const f = fixture(); const { data, cookie } = await f.start();
    assert.equal((await f.request("cancel", { challengeId: data.challengeId }, cookie)).status, 200);
    assert.equal(f.challenges.size, 0); assert.equal(f.users.size, 0); assert.equal(f.saved.length, 0);
    assert.equal((await f.request("verify", { challengeId: data.challengeId, credential: {} }, cookie)).status, 409);
});

test("another browser cannot verify or cancel a question", async () => {
    const f = fixture(); const a = await f.start(); const b = await f.start();
    assert.equal((await f.request("verify", { challengeId: a.data.challengeId, credential: {} }, b.cookie)).status, 409);
    await f.request("cancel", { challengeId: a.data.challengeId }, b.cookie);
    assert.ok(f.challenges.has(a.data.challengeId));
    assert.equal((await f.request("verify", { challengeId: a.data.challengeId }, undefined)).status, 401);
});

test("expired question and failed verification save nothing", async () => {
    const f = fixture(); const a = await f.start();
    f.challenges.get(a.data.challengeId).expires_at = new Date(0).toISOString();
    assert.equal((await f.request("verify", { challengeId: a.data.challengeId, credential: {} }, a.cookie)).status, 409);
    const b = await f.start();
    const response = await f.request("verify", { challengeId: b.data.challengeId, credential: { invalid: true } }, b.cookie);
    assert.equal(response.status, 400);
    assert.ok(!(await response.text()).includes("DO_NOT_LEAK"));
    assert.equal(f.users.size, 0); assert.equal(f.saved.length, 0);
});

test("cross-origin and invalid labels are refused; unsigned list requests get 401", async () => {
    const f = fixture();
    assert.equal((await f.handle(new Request(`${origin}/api/passkeys?action=options`, { method: "POST", headers: { Origin: "https://other.example", "Content-Type": "application/json" }, body: "{}" }))).status, 403);
    assert.equal((await f.request("options", { name: "", storage: "device" })).status, 400);
    assert.equal((await f.request("list")).status, 401);
});

test("missing server credentials never fall back to browser/public access", () => {
    assert.throws(() => createDatabase(), /database_not_configured/);
});

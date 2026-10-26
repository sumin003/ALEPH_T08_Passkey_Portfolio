import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { setup, userA, userB } from '../tests/helpers/flow-fixture.mjs';

// Sends Web Requests through the production handlers with a test-only injected DB/verifier.
// This report is NEVER a claim of real browser, network, or cryptographic verification.
export async function verifyCard5() {
    const f = setup(), entries = [];
    const a = await f.login('key-A'), b = await f.login('key-B');
    const secrets = [a.session, b.session, a.flow, b.flow].map(value => value.slice(value.indexOf('=') + 1));
    async function probe(id, account, path, { body, cookie, method, expected, owner, handler = f.privateInfo } = {}) {
        let req = f.request(path, body, cookie);
        if (method) req = new Request(req, { method });
        const response = await handler(req);
        const text = await response.text();
        const result = text ? JSON.parse(text) : null;
        assert.equal(response.status, expected, id);
        if (owner) {
            assert.equal(result.items.length, 3, id);
            assert.ok(result.items.every(item => item.content.startsWith(owner + ' private test marker')), id);
            assert.ok(!text.includes((owner === 'A' ? 'B' : 'A') + ' private test marker'), id);
        } else assert.ok(!result?.items, id + ' must not return private records');
        entries.push({ id, account, request: { method: req.method, path,
            headers: { ...(cookie ? { Cookie: '[REDACTED]' } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json', Origin: new URL(req.url).origin }) },
            ...(body === undefined ? {} : { body }) },
            response: { status: response.status, cacheControl: response.headers.get('cache-control'), body: result }, passed: true });
    }
    await probe('anonymous-denied', 'none', '/api/private-info', { expected: 401 });
    await probe('A-own', 'A', '/api/private-info', { cookie: a.session, expected: 200, owner: 'A' });
    await probe('A-to-B', 'A', `/api/private-info?userId=${userB}`, { cookie: a.session, expected: 403 });
    await probe('B-own', 'B', '/api/private-info', { cookie: b.session, expected: 200, owner: 'B' });
    await probe('B-to-A', 'B', `/api/private-info?userId=${userA}`, { cookie: b.session, expected: 403 });
    await probe('A-body-tamper', 'A', '/api/private-info', { cookie: a.session, body: { userId: userB, user_id: userB, owner_id: userB }, expected: 200, owner: 'A' });
    await probe('B-body-tamper', 'B', '/api/private-info', { cookie: b.session, body: { userId: userA }, expected: 200, owner: 'B' });
    await probe('used-challenge', 'A', '/api/auth?action=verify', { cookie: a.flow, body: a.body, handler: f.auth, expected: 409 });
    const bad = await f.start(); secrets.push(bad.flow.split('=')[1]);
    await probe('invalid-signature', 'A', '/api/auth?action=verify', { cookie: bad.flow,
        body: { challengeId: bad.data.challengeId, credential: { id: 'key-A', invalid: true, response: {} } }, handler: f.auth, expected: 401 });
    f.keys.delete('key-A'); // Simulates a server registration already removed; deletion itself is tested in card4.test.mjs.
    const removed = await f.start(); secrets.push(removed.flow.split('=')[1]);
    await probe('deleted-key', 'A', '/api/auth?action=verify', { cookie: removed.flow,
        body: { challengeId: removed.data.challengeId, credential: { id: 'key-A', response: {} } }, handler: f.auth, expected: 401 });
    const logout = await f.auth(f.request('/api/auth?action=logout', {}, b.session));
    assert.equal(logout.status, 200);
    await probe('old-cookie-after-logout', 'B', '/api/private-info', { cookie: b.session, expected: 401 });
    const report = { mode: 'LOCAL_SIMULATION', generatedAt: new Date().toISOString(),
        limitations: ['In-memory DB and mocked WebAuthn verifier; not real device or deployment HTTP evidence.',
            'Private records are synthetic. No actual account or user content is loaded.',
            'Cookie values omitted. Production handlers do not expose a test bypass.'],
        loginSetup: { A: { status: 200, authenticated: true }, B: { status: 200, authenticated: true } },
        passed: entries.length, entries };
    const serialized = JSON.stringify(report);
    for (const secret of secrets) assert.ok(!serialized.includes(secret), 'Report must not contain raw cookie values');
    return report;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    try { console.log(JSON.stringify(await verifyCard5(), null, 2)); }
    catch (error) { console.error('Card 5 verification failed:', error.message); process.exitCode = 1; }
}

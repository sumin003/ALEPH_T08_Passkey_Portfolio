import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyCard5 } from '../scripts/verify-card5.mjs';
import { setup, origin, userA, userB } from './helpers/flow-fixture.mjs';

test('two accounts, bidirectional tampering, four denial flows and masked evidence (local simulation)', async () => {
    const report = await verifyCard5();
    assert.equal(report.mode, 'LOCAL_SIMULATION');
    assert.equal(report.passed, 11);
    assert.ok(report.entries.every(entry => entry.passed));
    assert.ok(report.entries.filter(e => e.request.headers.Cookie).every(e => e.request.headers.Cookie === '[REDACTED]'));
});
test('all duplicate query selectors are checked and unauthorized queries never return records', async () => {
    const f = setup(), a = await f.login();
    for (const name of ['userId', 'user_id', 'owner_id']) {
        for (const value of [userB, `${userA}&${name}=${userB}`, `${userB}&${name}=${userA}`]) {
            const response = await f.privateInfo(f.request(`/api/private-info?${name}=${value}`, undefined, a.session));
            assert.equal(response.status, 403); assert.deepEqual(await response.json(), { error: 'FORBIDDEN' });
        }
    }
});
test('POST read is same-origin, bounded JSON only and cannot change either account', async () => {
    const f = setup(), a = await f.login();
    const foreign = await f.privateInfo(f.request('/api/private-info', { userId: userB }, a.session, { Origin: 'https://other.example' }));
    assert.equal(foreign.status, 403);
    const missing = await f.privateInfo(new Request(origin + '/api/private-info', { method: 'POST', headers: { Cookie: a.session, 'Content-Type': 'application/json' }, body: '{}' }));
    assert.equal(missing.status, 403);
    const huge = await f.privateInfo(f.request('/api/private-info', { value: 'x'.repeat(65536) }, a.session));
    assert.equal(huge.status, 413);
    const bad = await f.privateInfo(new Request(origin + '/api/private-info', { method: 'POST', headers: { Cookie: a.session, Origin: origin, 'Content-Type': 'application/json' }, body: 'invalid' }));
    assert.equal(bad.status, 400);
    const wrongType = await f.privateInfo(f.request('/api/private-info', {}, a.session, { 'Content-Type': 'text/plain' }));
    assert.equal(wrongType.status, 415);
    for (const method of ['PUT', 'PATCH', 'DELETE']) {
        const response = await f.privateInfo(new Request(origin + '/api/private-info', { method, headers: { Cookie: a.session } }));
        assert.equal(response.status, 405);
    }
    const normal = await f.privateInfo(f.request('/api/private-info', undefined, a.session));
    assert.ok((await normal.json()).items.every(item => item.content.startsWith('A private test marker')));
});
test('HEAD has no body and session/selector forgery never bypasses authentication', async () => {
    const f = setup(), a = await f.login();
    const head = await f.privateInfo(new Request(origin + '/api/private-info', { method: 'HEAD', headers: { Cookie: a.session } }));
    assert.equal(head.status, 200); assert.equal(await head.text(), '');
    for (const cookie of ['', '__Host-t08_enrollment=' + 'a'.repeat(43), a.session + '; ' + a.session]) {
        const response = await f.privateInfo(f.request('/api/private-info', { userId: userA, authenticated: true }, cookie));
        assert.equal(response.status, 401);
    }
});

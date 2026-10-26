import test from 'node:test';
import assert from 'node:assert/strict';
import { setup, origin, userB } from './helpers/flow-fixture.mjs';

test('login questions are fresh and stored server-side with browser binding', async () => {
    const f = setup(); const a = await f.start(), b = await f.start();
    assert.notEqual(a.data.options.challenge, b.data.options.challenge);
    assert.equal(f.questions.get(a.data.challengeId).challenge, a.data.options.challenge);
    assert.equal(f.sessions.size, 0);
});
test('verified login issues secure opaque cookie and only returns owner items (verifier mocked)', async () => {
    const f = setup(); const login = await f.login();
    assert.match(login.setCookie, /Secure; HttpOnly; SameSite=Strict/);
    assert.equal(f.checked.expectedChallenge, login.data.options.challenge);
    assert.equal(f.checked.expectedOrigin, origin); assert.equal(f.checked.requireUserVerification, true);
    assert.ok(f.checked.credential.publicKey instanceof Uint8Array);
    const res = await f.privateInfo(f.request('/api/private-info', undefined, login.session));
    assert.equal(res.status, 200); assert.match(res.headers.get('cache-control'), /no-store/);
    const body = await res.text(); assert.ok(body.includes('A private test marker')); assert.ok(!body.includes('B private test marker'));
});
test('invalid signature saves no session; replay of successful request is rejected', async () => {
    const f = setup(); const { data, flow } = await f.start();
    const bad = await f.auth(f.request('/api/auth?action=verify', { challengeId: data.challengeId, credential: { id: 'key-A', invalid: true, response: {} } }, flow));
    assert.equal(bad.status, 401); assert.ok(!(await bad.text()).includes('SECRET_TEST')); assert.equal(f.sessions.size, 0);
    const login = await f.login();
    assert.equal((await f.auth(f.request('/api/auth?action=verify', login.body, login.flow))).status, 409);
});
test('wrong browser binding, user handle, unknown key and expired question cannot log in', async () => {
    const f = setup(); const a = await f.start(), b = await f.start();
    const body = { challengeId: a.data.challengeId, credential: { id: 'key-A', response: {} } };
    assert.equal((await f.auth(f.request('/api/auth?action=verify', body, b.flow))).status, 409);
    body.credential.response.userHandle = 'handleB';
    assert.equal((await f.auth(f.request('/api/auth?action=verify', body, a.flow))).status, 401);
    body.credential = { id: 'unknown', response: {} };
    assert.equal((await f.auth(f.request('/api/auth?action=verify', body, a.flow))).status, 401);
    f.questions.get(a.data.challengeId).expires_at = new Date(0).toISOString();
    assert.equal((await f.auth(f.request('/api/auth?action=verify', body, a.flow))).status, 409);
    assert.equal(f.sessions.size, 0);
});
test('logout revokes the server session: the exact old cookie cannot read data again', async () => {
    const f = setup(); const { session } = await f.login();
    assert.equal((await f.auth(f.request('/api/auth?action=logout', {}, session))).status, 200);
    assert.equal((await f.privateInfo(f.request('/api/private-info', undefined, session))).status, 401);
    assert.equal((await f.auth(f.request('/api/auth?action=session', undefined, session))).status, 401);
});
test('session expiry and rotation invalidate earlier session cookies', async () => {
    const f = setup(); const first = await f.login(); const second = await f.login('key-A', first.session);
    assert.equal((await f.privateInfo(f.request('/api/private-info', undefined, first.session))).status, 401);
    assert.equal((await f.privateInfo(f.request('/api/private-info', undefined, second.session))).status, 200);
    for (const s of f.sessions.values()) s.expires_at = new Date(0).toISOString();
    assert.equal((await f.privateInfo(f.request('/api/private-info', undefined, second.session))).status, 401);
});
test('cross-user selectors are forbidden; enrollment cookie is not a login session', async () => {
    const f = setup(); const { session } = await f.login();
    assert.equal((await f.privateInfo(f.request('/api/private-info?userId=' + userB, undefined, session))).status, 403);
    assert.equal((await f.privateInfo(f.request('/api/private-info', undefined, '__Host-t08_enrollment=' + 'a'.repeat(43)))).status, 401);
    assert.equal((await f.privateInfo(f.request('/api/private-info', undefined, '__Host-t08_session=' + 'b'.repeat(43)))).status, 401);
});
test('cross-site logout is forbidden and cancelling a login does not issue a session', async () => {
    const f = setup(); const { session } = await f.login();
    assert.equal((await f.auth(f.request('/api/auth?action=logout', {}, session, { Origin: 'https://evil.example' }))).status, 403);
    assert.equal((await f.privateInfo(f.request('/api/private-info', undefined, session))).status, 200);
    const { data, flow } = await f.start();
    assert.equal((await f.auth(f.request('/api/auth?action=cancel', { challengeId: data.challengeId }, flow))).status, 200);
    assert.ok(!f.questions.has(data.challengeId));
});

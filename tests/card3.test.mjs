import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createAuthenticationHandler, createPrivateInfoHandler } from '../server/authentication.mjs';
import { RequestError } from '../server/registration.mjs';
const origin = 'https://alepht08passkeyportfolio.vercel.app';
const userA = '11111111-1111-4111-8111-111111111111';
const userB = '22222222-2222-4222-8222-222222222222';
function setup() {
    const questions = new Map(), sessions = new Map();
    const keys = new Map([['key-A', { credential_id: 'key-A', user_id: userA, public_key: 'AQID', counter: 0, transports: ['internal'] }],
        ['key-B', { credential_id: 'key-B', user_id: userB, public_key: 'BAUG', counter: 0, transports: ['internal'] }]]);
    let checked;
    const db = { async request(path, method = 'GET', body) {
        const [table, query = ''] = path.split('?'); const p = new URLSearchParams(query);
        const eq = name => p.get(name)?.replace(/^eq\./, '');
        if (table === 't08_auth_challenges') {
            if (method === 'POST') { questions.set(body.id, { ...body }); return [body]; }
            const row = questions.get(eq('id'));
            const matches = row && row.binding_hash === eq('binding_hash');
            if (method === 'DELETE') { if (matches && !row.used_at) questions.delete(row.id); return []; }
            return matches ? [row] : [];
        }
        if (table === 't08_passkeys') return keys.has(eq('credential_id')) ? [keys.get(eq('credential_id'))] : [];
        if (table === 't08_users') return [{ webauthn_user_id: eq('id') === userA ? 'handleA' : 'handleB' }];
        if (table === 'rpc/t08_finish_login') {
            const q = questions.get(body.p_challenge_id), key = keys.get(body.p_credential_id);
            if (!q || q.used_at || q.binding_hash !== body.p_binding_hash || Date.parse(q.expires_at) <= Date.now()) throw new RequestError(409, 'CHALLENGE_USED', 'Used');
            assert.equal(key.counter, body.p_expected_counter);
            q.used_at = new Date().toISOString(); key.counter = body.p_new_counter;
            if (sessions.has(body.p_previous_session_hash)) sessions.get(body.p_previous_session_hash).revoked_at = 'revoked';
            sessions.set(body.p_session_hash, { user_id: key.user_id, expires_at: new Date(Date.now() + 3600000).toISOString() });
            return key.user_id;
        }
        if (table === 't08_sessions') {
            const row = sessions.get(eq('token_hash'));
            if (method === 'PATCH') { if (row) row.revoked_at = body.revoked_at; return []; }
            return row && !row.revoked_at && Date.parse(row.expires_at) > Date.now() ? [row] : [];
        }
        if (table === 't08_private_items') return [1, 2, 3].map(id => ({ id, title: 'private draft', content: eq('user_id') === userA ? 'A private test marker' : 'B private test marker' }));
        throw Error('Unexpected DB operation');
    } };
    // Application-flow tests only. The production cryptographic verifier is not bypassed.
    const library = async () => ({
        generateAuthenticationOptions: async options => ({ challenge: randomBytes(32).toString('base64url'), rpId: options.rpID, userVerification: options.userVerification }),
        verifyAuthenticationResponse: async args => {
            checked = args;
            if (args.response.invalid) throw Error('INVALID_SIGNATURE_SECRET_TEST');
            return { verified: true, authenticationInfo: { newCounter: args.credential.counter + 1 } };
        }
    });
    const auth = createAuthenticationHandler({ database: () => db, library, configuration: () => ({ origin, rpID: new URL(origin).hostname }) });
    const privateInfo = createPrivateInfoHandler({ database: () => db });
    const request = (path, body, cookie, extra = {}) => new Request(origin + path, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { Origin: origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(cookie ? { Cookie: cookie } : {}), ...extra },
        body: body === undefined ? undefined : JSON.stringify(body)
    });
    async function start() {
        const response = await auth(request('/api/auth?action=options', {}));
        assert.equal(response.status, 200);
        return { data: await response.json(), flow: response.headers.getSetCookie()[0].split(';')[0] };
    }
    async function login(id = 'key-A', previous) {
        const { data, flow } = await start();
        const body = { challengeId: data.challengeId, credential: { id, response: { userHandle: id === 'key-A' ? 'handleA' : 'handleB' } } };
        const response = await auth(request('/api/auth?action=verify', body, flow + (previous ? '; ' + previous : '')));
        assert.equal(response.status, 200);
        const setCookie = response.headers.getSetCookie().find(s => s.startsWith('__Host-t08_session='));
        return { session: setCookie.split(';')[0], setCookie, flow, body, data };
    }
    return { auth, privateInfo, request, start, login, questions, sessions, get checked() { return checked; } };
}

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

// In-memory application-flow fixture. Does not simulate real WebAuthn cryptography.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createAuthenticationHandler, createPrivateInfoHandler } from '../../server/authentication.mjs';
import { RequestError } from '../../server/registration.mjs';
export const origin = 'https://alepht08passkeyportfolio.vercel.app';
export const userA = '11111111-1111-4111-8111-111111111111';
export const userB = '22222222-2222-4222-8222-222222222222';
export function setup() {
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
        if (table === 't08_private_items') {
            const records = [userA, userB].flatMap((owner, index) => [1, 2, 3].map(id => ({ id: `${index}-${id}`, user_id: owner, kind: ['project-note', 'personal-goal', 'reflection'][id - 1], title: '가상 검증 항목 ' + id, content: `${index === 0 ? 'A' : 'B'} private test marker ${id}` })));
            return records.filter(row => row.user_id === eq('user_id')).map(({ user_id, ...item }) => item);
        }
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
    const privateInfo = createPrivateInfoHandler({ database: () => db, configuration: () => ({ origin }) });
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
    return { auth, privateInfo, request, start, login, questions, sessions, keys, get checked() { return checked; } };
}


import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createRegistrationHandler } from '../server/registration.mjs';
const origin = 'https://alepht08passkeyportfolio.vercel.app';
const user = '11111111-1111-4111-8111-111111111111';
const token = randomBytes(32).toString('base64url');
const tokenHash = createHash('sha256').update(token).digest('hex');
const cookie = '__Host-t08_session=' + token;
function fixture() {
    let active = true; const rows = new Map(); let generated;
    const keys = [{ credential_id: 'first-key', user_id: user, name: 'first', transports: ['internal'] }];
    const db = {
        findEnrollment: async () => null,
        list: async () => keys,
        create: async row => rows.set(row.id, row),
        findChallenge: async (id, hash) => rows.get(id)?.binding_hash === hash ? rows.get(id) : null,
        cancel: async () => {},
        finish: async () => assert.fail('Additional registration must not create a new user'),
        request: async (path, method, body) => {
            if (path.startsWith('t08_sessions?')) return active && path.includes(tokenHash) ? [{ user_id: user, expires_at: new Date(Date.now() + 600000).toISOString() }] : [];
            if (path.startsWith('t08_users?')) return [{ webauthn_user_id: 'dXNlci1oYW5kbGU' }];
            if (path.startsWith('t08_passkeys?')) return keys;
            if (path === 'rpc/t08_finish_additional_registration') {
                assert.equal(body.p_session_hash, tokenHash);
                const q = rows.get(body.p_challenge_id);
                assert.equal(q.existing_user_id, user); assert.equal(q.registration_session_hash, tokenHash);
                q.used_at = new Date().toISOString();
                keys.push({ credential_id: body.p_credential_id, user_id: user, name: q.passkey_name }); return user;
            }
            if (path === 'rpc/t08_remove_passkey') {
                assert.equal(body.p_session_hash, tokenHash);
                if (!active) return { error: 'AUTH_REQUIRED' };
                const index = keys.findIndex(k => k.credential_id === body.p_credential_id);
                if (index < 0) return { error: 'PASSKEY_NOT_FOUND' };
                if (keys.length === 1) return { error: 'LAST_PASSKEY' };
                keys.splice(index, 1); active = false; return { deleted: true, remaining: keys.length, loggedOut: true };
            }
            assert.fail('Unexpected request ' + path);
        }
    };
    const library = async () => ({
        generateRegistrationOptions: async args => {
            generated = args;
            return { challenge: randomBytes(32).toString('base64url'), user: { id: Buffer.from(args.userID).toString('base64url') } };
        },
        verifyRegistrationResponse: async () => ({ verified: true, registrationInfo: {
            credential: { id: 'second-key', publicKey: new Uint8Array([1, 2]), counter: 0 }, credentialDeviceType: 'multiDevice', credentialBackedUp: true
        } })
    });
    const handle = createRegistrationHandler({ database: () => db, library, configuration: () => ({ origin, rpID: new URL(origin).hostname }) });
    const request = (action, body, value = cookie) => handle(new Request(`${origin}/api/passkeys?action=${action}`, {
        method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', Cookie: value }, body: JSON.stringify(body)
    }));
    return { request, rows, keys, get generated() { return generated; }, revoke() { active = false; } };
}
test('additional registration reuses owner/user handle and excludes existing keys (verifier mocked)', async () => {
    const f = fixture();
    const response = await f.request('options', { name: 'backup', storage: 'second device', userId: 'attacker' });
    assert.equal(response.status, 200); const data = await response.json();
    const binding = response.headers.getSetCookie()[0].split(';')[0];
    assert.equal(f.rows.get(data.challengeId).candidate_user_id, user);
    assert.equal(Buffer.from(f.generated.userID).toString('base64url'), 'dXNlci1oYW5kbGU');
    assert.equal(f.generated.excludeCredentials[0].id, 'first-key');
    const verified = await f.request('verify', { challengeId: data.challengeId, credential: {} }, cookie + '; ' + binding);
    assert.equal(verified.status, 200); assert.equal((await verified.json()).additional, true);
    assert.equal(f.keys.length, 2); assert.ok(f.keys.every(k => k.user_id === user));
});
test('logging out between additional registration options and verification prevents saving', async () => {
    const f = fixture(); const response = await f.request('options', { name: 'backup', storage: 'device' });
    const data = await response.json(), binding = response.headers.getSetCookie()[0].split(';')[0];
    f.revoke();
    assert.equal((await f.request('verify', { challengeId: data.challengeId, credential: {} }, cookie + '; ' + binding)).status, 401);
    assert.equal(f.keys.length, 1);
});
test('last key is rejected by the server; deleting from two logs out and preserves the remaining key', async () => {
    const f = fixture();
    const last = await f.request('delete', { credentialId: 'first-key' });
    assert.equal(last.status, 409); assert.equal((await last.json()).error, 'LAST_PASSKEY');
    f.keys.push({ credential_id: 'backup-key', user_id: user, name: 'backup' });
    const deleted = await f.request('delete', { credentialId: 'first-key' });
    assert.equal(deleted.status, 200); assert.equal((await deleted.json()).remaining, 1);
    assert.ok(deleted.headers.getSetCookie().every(s => s.includes('Max-Age=0')));
    assert.equal(f.keys[0].credential_id, 'backup-key');
    assert.equal((await f.request('delete', { credentialId: 'backup-key' })).status, 401);
});
test('anonymous deletion and other-account credential ID are rejected', async () => {
    const f = fixture();
    assert.equal((await f.request('delete', { credentialId: 'first-key' }, '')).status, 401);
    assert.equal((await f.request('delete', { credentialId: 'another-user-key' })).status, 404);
    assert.equal(f.keys.length, 1);
});

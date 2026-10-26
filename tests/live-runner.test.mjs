import test from 'node:test';
import assert from 'node:assert/strict';
import { TestClient, fixtureSQL, ORIGIN } from '../scripts/verify-live.mjs';

test('live evidence masks every cookie while replay sends the exact old cookie', async () => {
    const entries = [], secrets = new Set(), sent = [];
    const token = 's'.repeat(43);
    let count = 0;
    const send = async (url, request) => {
        sent.push({ url, ...request }); count++;
        if (count === 1) return Response.json({ authenticated: true }, { headers: { 'Set-Cookie': '__Host-t08_session=' + token + '; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=3600' } });
        if (count === 2) return Response.json({ loggedOut: true }, { headers: { 'Set-Cookie': '__Host-t08_session=; Secure; HttpOnly; Max-Age=0' } });
        return Response.json({ error: 'AUTH_REQUIRED' }, { status: 401 });
    };
    const client = new TestClient('test', entries, secrets, send);
    await client.request('login', '/api/auth?action=verify', {}, 200);
    const original = client.cookieHeader();
    await client.request('logout', '/api/auth?action=logout', {}, 200);
    assert.equal(client.cookieHeader(), '');
    await client.request('replay', '/api/private-info', undefined, 401, original);
    assert.equal(sent[2].headers.Cookie, original);
    assert.equal(sent[2].url, ORIGIN + '/api/private-info');
    assert.ok(!JSON.stringify(entries).includes(token));
    assert.ok(secrets.has(token));
});
test('live evidence fails on unexpected status and redacts unexpected private content', async () => {
    const entries = [];
    const client = new TestClient('A', entries, new Set(), async () => Response.json({ items: [{ id: 'other', title: 'real title', content: 'DO_NOT_PUBLISH_REAL_CONTENT' }] }));
    await client.request('unexpected-content', '/api/private-info', undefined, 200);
    assert.ok(!JSON.stringify(entries).includes('DO_NOT_PUBLISH_REAL_CONTENT'));
    await assert.rejects(client.request('wrong-status', '/api/private-info', undefined, 403));
    assert.equal(entries[1].passed, false);
});
test('seed SQL checks new test account ownership/public keys and includes only synthetic notes', () => {
    const accounts = [
        { label: 'A', id: '11111111-1111-4111-8111-111111111111', handle: 'handle-a', key: { id: 'test-key-a', publicKeyCose: 'public-a' } },
        { label: 'B', id: '22222222-2222-4222-8222-222222222222', handle: 'handle-b', key: { id: 'test-key-b', publicKeyCose: 'public-b' } }
    ];
    const sql = fixtureSQL(accounts, { id: '33333333-3333-4333-8333-333333333333', challengeId: '44444444-4444-4444-8444-444444444444' });
    assert.equal((sql.match(/public_key=/g) || []).length, 2);
    assert.equal((sql.match(/가상 [AB]:/g) || []).length, 6);
    assert.ok(sql.includes('Cancellation state unexpected'));
    assert.ok(sql.includes('begin;') && sql.endsWith('commit;\n'));
    assert.ok(!/delete\s+from|truncate|alter\s+table/i.test(sql));
});

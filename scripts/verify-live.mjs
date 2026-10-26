// Real HTTPS checks with test-only software credentials. Never imported by the website.
// Does not use the user's passkeys, device PIN, DB secret or existing browser cookies.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { makeSoftwareAuthenticator, accountId } from './testing/software-authenticator.mjs';
export const ORIGIN = 'https://alepht08passkeyportfolio.vercel.app';
export const notes = {
    A: ['가상 A: API 응답 구조를 정리하는 연습 프로젝트.', '가상 A: 테스트 시나리오 3개 작성.', '가상 A: 요청과 응답을 나눠 기록하는 연습.'],
    B: ['가상 B: 화면 접근성을 살펴보는 연습 프로젝트.', '가상 B: 키보드 이동 순서 5개 확인.', '가상 B: 작은 단위로 화면을 점검하는 연습.']
};
const kinds = ['project-note', 'personal-goal', 'reflection'];
const titles = ['준비 중인 프로젝트 메모', '개인 목표와 진행 상황', '스스로 쓰는 회고'];
const sqlQuote = value => "'" + String(value).replaceAll("'", "''") + "'";
export function fixtureSQL(accounts, cancelled) {
    let sql = 'begin;\ndo $guard$ begin\n';
    for (const a of accounts) {
        assert.match(a.id, /^[a-f0-9-]{36}$/i);
        sql += `if not exists(select 1 from public.t08_users u join public.t08_passkeys k on k.user_id=u.id where u.id=${sqlQuote(a.id)}::uuid and u.webauthn_user_id=${sqlQuote(a.handle)} and k.credential_id=${sqlQuote(a.key.id)} and k.public_key=${sqlQuote(a.key.publicKeyCose)}) then raise exception 'Test account/public key mismatch'; end if;\n`;
    }
    sql += `if exists(select 1 from public.t08_users where id=${sqlQuote(cancelled.id)}::uuid) or exists(select 1 from public.t08_challenges where id=${sqlQuote(cancelled.challengeId)}::uuid) then raise exception 'Cancellation state unexpected'; end if;\nend; $guard$;\n`;
    for (const a of accounts) {
        sql += 'insert into public.t08_private_items(user_id,kind,title,content) values\n';
        sql += kinds.map((kind, index) => `(${sqlQuote(a.id)}::uuid,${sqlQuote(kind)},${sqlQuote(titles[index])},${sqlQuote(notes[a.label][index])})`).join(',\n');
        sql += '\non conflict(user_id,kind) do update set content=excluded.content;\n';
    }
    return sql + "select 'Two new test accounts seeded; public keys and cancellation checked' as result;\ncommit;\n";
}
function publicBody(body) {
    if (!Array.isArray(body?.items)) return body;
    const allowed = new Set([...notes.A, ...notes.B, '']);
    return { ...body, items: body.items.map(item => allowed.has(item.content) ? item : { id: '[REDACTED]', title: '[REDACTED]', content: '[REDACTED_UNEXPECTED_CONTENT]' }) };
}
export class TestClient {
    constructor(label, entries, secrets, send = fetch) { this.label = label; this.entries = entries; this.secrets = secrets; this.send = send; this.cookies = new Map(); }
    cookieHeader() { return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '); }
    async request(id, route, body, expected, cookieOverride) {
        const cookie = cookieOverride ?? this.cookieHeader();
        const method = body === undefined ? 'GET' : 'POST';
        const headers = { ...(cookie ? { Cookie: cookie } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json', Origin: ORIGIN }) };
        let response;
        try { response = await this.send(ORIGIN + route, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(20000) }); }
        catch { throw new Error(`${id}: HTTPS 연결 실패. 보고서는 완료로 표시되지 않습니다.`); }
        const setCookies = response.headers.getSetCookie();
        for (const item of setCookies) {
            const pair = item.split(';')[0], index = pair.indexOf('=');
            const name = pair.slice(0, index), value = pair.slice(index + 1);
            if (value) this.secrets.add(value);
            if (!value || /Max-Age=0(?:;|$)/i.test(item)) this.cookies.delete(name); else this.cookies.set(name, value);
        }
        let data;
        try { data = await response.json(); } catch { throw new Error(`${id}: JSON 응답 아님 (HTTP ${response.status}).`); }
        const entry = { id, account: this.label, request: { method, route,
            headers: { ...(cookie ? { Cookie: '[REDACTED]' } : {}), ...(body === undefined ? {} : { Origin: ORIGIN, 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body }) },
            response: { status: response.status, headers: { 'Cache-Control': response.headers.get('cache-control'),
                ...(setCookies.length ? { 'Set-Cookie': setCookies.map(value => value.split('=')[0] + '=[REDACTED]; ' + value.split(';').slice(1).join(';').trim()) } : {}) }, body: publicBody(data) },
            passed: response.status === expected };
        this.entries.push(entry);
        assert.equal(response.status, expected, `${id}: unexpected status`);
        return data;
    }
}
function ownItems(body, label) {
    assert.equal(body.items?.length, 3, `${label}: expected 3 private items`);
    assert.deepEqual(body.items.map(i => i.content).sort(), [...notes[label]].sort(), `${label}: unexpected owner/content`);
}
export async function runLive() {
    const output = path.resolve('artifacts', 't08-live-' + Date.now());
    const entries = [], secrets = new Set();
    const report = { mode: 'REAL_HTTPS_SOFTWARE_AUTHENTICATOR', origin: ORIGIN, startedAt: new Date().toISOString(), completed: false,
        nativeDeviceVerification: false, verifierMocked: false,
        description: '실제 HTTPS 서버의 공개키 검증을 호출합니다. 테스트용 소프트웨어 인증기이며 Windows Hello/휴대폰/PIN 검사가 아닙니다.', testAccounts: [], entries };
    const a = new TestClient('A', entries, secrets), b = new TestClient('B', entries, secrets), c = new TestClient('cancelled', entries, secrets);
    const a1 = makeSoftwareAuthenticator(), a2 = makeSoftwareAuthenticator(), b1 = makeSoftwareAuthenticator();
    async function register(client, key, name, expectedHandle) {
        const options = await client.request(name + '-options', '/api/passkeys?action=options', { name, storage: '자동 검사 전용 소프트웨어 인증기' }, 200);
        if (expectedHandle) assert.equal(options.options.user.id, expectedHandle);
        const response = key.registration(options.options, ORIGIN);
        const saved = await client.request(name + '-registered', '/api/passkeys?action=verify', { challengeId: options.challengeId, credential: response }, 200);
        assert.equal(saved.registered, true);
        assert.equal(saved.additional, !!expectedHandle);
        if (!expectedHandle) report.testAccounts.push({ label: client.label, id: accountId(options.options.user.id), publicKeyCose: key.publicKeyCose });
        return { id: accountId(options.options.user.id), handle: options.options.user.id, challenge: options.options.challenge, key };
    }
    async function login(client, key, id) {
        const options = await client.request(id + '-options', '/api/auth?action=options', {}, 200);
        const cookie = client.cookieHeader();
        const body = { challengeId: options.challengeId, credential: key.assertion(options.options, ORIGIN) };
        const result = await client.request(id + '-success', '/api/auth?action=verify', body, 200);
        assert.equal(result.authenticated, true);
        return { cookie, body, challenge: options.options.challenge };
    }
    await mkdir(output, { recursive: true });
    try {
        // Preflight is read-only. A blocked destination creates no test accounts.
        await c.request('anonymous-private-denied', '/api/private-info', undefined, 401);
        if (!stdin.isTTY) throw new Error('SQL 실행 확인이 필요한 대화형 터미널에서 실행해 주세요.');
        const A = { ...await register(a, a1, '제출 검증 A 기본'), label: 'A' };
        await login(a, a1, 'A-first-login');
        const backup = await register(a, a2, '제출 검증 A 백업', A.handle);
        assert.equal(backup.id, A.id);
        assert.notEqual(A.challenge, backup.challenge);
        const B = { ...await register(b, b1, '제출 검증 B 기본'), label: 'B' };
        assert.notEqual(A.id, B.id);
        await login(b, b1, 'B-first-login');
        const cancelled = await c.request('cancel-options', '/api/passkeys?action=options', { name: '취소 검증', storage: '자동 검사 전용 소프트웨어 인증기' }, 200);
        const cancelState = { id: accountId(cancelled.options.user.id), challengeId: cancelled.challengeId };
        await c.request('registration-cancel', '/api/passkeys?action=cancel', { challengeId: cancelled.challengeId }, 200);
        await c.request('cancelled-has-no-key-list', '/api/passkeys?action=list', undefined, 401);
        const sqlFile = path.join(output, 'seed-two-test-accounts.sql');
        await writeFile(sqlFile, fixtureSQL([A, B], cancelState));
        console.log('새 테스트 계정 A/B 등록 완료. 기존 사용자 계정은 사용하지 않았습니다.');
        console.log('Supabase SQL Editor에서 다음 파일 내용을 실행해 주세요:\n' + sqlFile);
        console.log('SQL은 방금 만든 계정과 공개키를 확인한 뒤 가상 본문 3개씩만 넣습니다.');
        const reader = createInterface({ input: stdin, output: stdout });
        try { await reader.question('SQL 실행 성공 후 이 터미널에서 Enter: '); } finally { reader.close(); }
        const beforeA = await a.request('A-own-before', '/api/private-info', undefined, 200); ownItems(beforeA, 'A');
        await a.request('A-to-B-denied', '/api/private-info?userId=' + B.id, undefined, 403);
        const afterA = await a.request('A-own-after', '/api/private-info', undefined, 200); ownItems(afterA, 'A');
        assert.deepEqual(afterA.items, beforeA.items);
        const beforeB = await b.request('B-own-before', '/api/private-info', undefined, 200); ownItems(beforeB, 'B');
        await b.request('B-to-A-denied', '/api/private-info?userId=' + A.id, undefined, 403);
        const afterB = await b.request('B-own-after', '/api/private-info', undefined, 200); ownItems(afterB, 'B');
        assert.deepEqual(afterB.items, beforeB.items);
        ownItems(await a.request('A-body-tamper', '/api/private-info', { userId: B.id, user_id: B.id, owner_id: B.id }, 200), 'A');
        ownItems(await b.request('B-body-tamper', '/api/private-info', { userId: A.id }, 200), 'B');
        const first = await login(a, a1, 'A-fresh-login');
        await a.request('used-question-replay', '/api/auth?action=verify', first.body, 409, first.cookie);
        const next = await a.request('A-next-options', '/api/auth?action=options', {}, 200);
        assert.notEqual(first.challenge, next.options.challenge);
        const correct = a1.assertion(next.options, ORIGIN);
        const otherKey = b1.assertion(next.options, ORIGIN);
        const wrong = { ...correct, response: { ...correct.response, signature: otherKey.response.signature } };
        await a.request('wrong-key-signature-denied', '/api/auth?action=verify', { challengeId: next.challengeId, credential: wrong }, 401);
        // Same untouched challenge + correct signature must now succeed.
        await a.request('correct-signature-accepted', '/api/auth?action=verify', { challengeId: next.challengeId, credential: correct }, 200);
        const oldCookie = b.cookieHeader();
        await b.request('B-logout', '/api/auth?action=logout', {}, 200);
        await b.request('B-exact-old-cookie-denied', '/api/private-info', undefined, 401, oldCookie);
        await login(b, b1, 'B-return-login');
        const list = await a.request('A-two-keys', '/api/passkeys?action=list', undefined, 200);
        assert.equal(list.passkeys.length, 2); assert.ok(list.passkeys.every(key => key.name && key.created_at));
        const removed = await a.request('A-delete-first-key', '/api/passkeys?action=delete', { credentialId: a1.id }, 200);
        assert.equal(removed.remaining, 1); assert.equal(removed.loggedOut, true);
        const deleted = await a.request('deleted-key-options', '/api/auth?action=options', {}, 200);
        await a.request('deleted-key-login-denied', '/api/auth?action=verify', { challengeId: deleted.challengeId, credential: a1.assertion(deleted.options, ORIGIN) }, 401);
        await login(a, a2, 'remaining-key-login');
        ownItems(await a.request('remaining-key-private', '/api/private-info', undefined, 200), 'A');
        await a.request('last-key-delete-denied', '/api/passkeys?action=delete', { credentialId: a2.id }, 409);
        report.completed = true;
    } catch (error) {
        report.failure = error instanceof assert.AssertionError ? '응답 상태 또는 소유자·가상 본문 검사가 실패했습니다.' : error.message;
        process.exitCode = 1;
    } finally {
        // Best-effort logout for test clients only. Does not touch the user's browser.
        for (const client of [a, b]) {
            if (client.cookies.has('__Host-t08_session')) {
                try { await client.request(client.label + '-final-logout', '/api/auth?action=logout', {}, 200); }
                catch { report.completed = false; report.failure = '테스트 세션 종료를 확인하지 못했습니다.'; process.exitCode = 1; }
            }
        }
        report.finishedAt = new Date().toISOString();
        report.passedRequests = entries.filter(e => e.passed).length;
        const serialized = JSON.stringify(report, null, 2);
        for (const secret of secrets) assert.ok(!serialized.includes(secret), 'Raw cookie must not be saved');
        const reportFile = path.join(output, 'evidence.json');
        await writeFile(reportFile, serialized + '\n');
        console.log((report.completed ? '검증 완료: ' : '검증 미완료: ') + reportFile);
        if (report.failure) console.log(report.failure);
    }
    return report;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    if (process.argv.includes('--help')) console.log(`실행: npm run verify:live\n정식 배포 서버에 새 테스트 계정 2개와 소프트웨어 공개키를 등록합니다.\n등록 뒤 출력되는 SQL을 Supabase SQL Editor에서 실행하고 Enter를 누르면 계속합니다.\n실제 서명 검증·양방향 격리·질문 재사용·옛 쿠키·삭제 키 거절을 기록합니다.\n기존 계정과 기기 패스키는 사용하지 않습니다. 비밀키는 파일이나 서버에 저장하지 않습니다.\n소프트웨어 인증기이므로 실제 기기/PIN 검증의 증거로 표시하지 않습니다.\n결과는 artifacts 아래에 저장되며 Git과 공개 빌드에서 제외됩니다.\n테스트 개인키는 종료하면 사라지며, 테스트 계정은 DB에 남습니다.`);
    else await runLive();
}

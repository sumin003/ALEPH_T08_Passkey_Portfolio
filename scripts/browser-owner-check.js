/* Paste this file into DevTools Console on the production site, then run:
   await t08CheckOwner('OTHER_TEST_ACCOUNT_UUID')
   Uses the current browser's HttpOnly session automatically. Never asks for a token.
   Use only synthetic private content when sharing the returned evidence. */
globalThis.t08CheckOwner = async function (otherUserId) {
    if (location.origin !== 'https://alepht08passkeyportfolio.vercel.app') throw new Error('정식 사이트에서 실행해 주세요.');
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(otherUserId)) throw new Error('상대 테스트 계정 UUID가 필요합니다.');
    const own = await fetch('/api/private-info', { credentials: 'same-origin', cache: 'no-store' });
    if (own.status !== 200) throw new Error('먼저 테스트 계정의 패스키로 로그인해 주세요.');
    const ownBody = await own.json();
    const entries = [{ request: { method: 'GET', path: '/api/private-info', Cookie: '[REDACTED]' }, response: { status: own.status, body: ownBody } }];
    for (const spec of [
        { path: '/api/private-info?userId=' + otherUserId, method: 'GET', expected: 403 },
        { path: '/api/private-info', method: 'POST', body: { userId: otherUserId, user_id: otherUserId, owner_id: otherUserId }, expected: 200 },
        { path: '/api/private-info', method: 'GET', anonymous: true, expected: 401 }
    ]) {
        const response = await fetch(spec.path, { method: spec.method, credentials: spec.anonymous ? 'omit' : 'same-origin', cache: 'no-store',
            ...(spec.body ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(spec.body) } : {}) });
        const body = await response.json();
        const correctScope = spec.method !== 'POST' || JSON.stringify(body.items) === JSON.stringify(ownBody.items);
        entries.push({ request: { method: spec.method, path: spec.path, ...(spec.anonymous ? {} : { Cookie: '[REDACTED]' }), ...(spec.body ? { body: spec.body } : {}) },
            response: { status: response.status, body }, passed: response.status === spec.expected && correctScope });
    }
    const result = { mode: 'LIVE_BROWSER_CURRENT_ACCOUNT', generatedAt: new Date().toISOString(),
        note: '한 계정의 실제 조회 검사. 다른 계정에서도 반대로 실행해야 합니다. 서명 재사용·삭제 검사는 별도입니다.', entries };
    console.log(JSON.stringify(result, null, 2));
    return result;
};

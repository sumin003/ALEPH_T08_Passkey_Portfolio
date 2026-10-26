(() => {
    const login = document.getElementById('passkey-login');
    const logout = document.getElementById('passkey-logout');
    const state = document.getElementById('private-state');
    const status = document.getElementById('private-status');
    const content = document.getElementById('private-content');
    const registration = document.querySelector('.passkey-registration');
    if (!login || !logout || !content) return;
    let busy = false; let version = 0; let expiryTimer;
    const channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('t08-session') : null;
    function lock(message = '패스키 로그인 후 비공개 정보를 확인할 수 있습니다.') {
        version++; clearTimeout(expiryTimer);
        content.replaceChildren(); content.hidden = true;
        state.textContent = '비공개 · 잠김'; status.textContent = message;
        login.hidden = false; logout.hidden = true; registration.hidden = false;
    }
    async function request(action, body) {
        const response = await fetch(`/api/auth?action=${action}`, {
            method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
            headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
            body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000)
        });
        let data;
        try { data = await response.json(); } catch { throw new Error('서버 응답을 확인하지 못했습니다.'); }
        if (!response.ok) throw new Error(data.message || '로그인 요청이 거절되었습니다.');
        return data;
    }
    function decode(value) {
        const v = value.replaceAll('-', '+').replaceAll('_', '/');
        return Uint8Array.from(atob(v + '='.repeat((4 - v.length % 4) % 4)), c => c.charCodeAt(0));
    }
    function encode(buffer) { return btoa(String.fromCharCode(...new Uint8Array(buffer))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
    async function refresh() {
        const attempt = ++version;
        try {
            const response = await fetch('/api/private-info', { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000) });
            if (attempt !== version) return;
            if (response.status === 401 || response.status === 403) { lock(); return; }
            if (!response.ok) throw new Error();
            const data = await response.json();
            if (attempt !== version) return;
            if (!Array.isArray(data.items)) throw new Error();
            content.replaceChildren();
            for (const item of data.items) {
                const article = document.createElement('article');
                const title = document.createElement('h4'); const text = document.createElement('p');
                title.textContent = item.title;
                text.textContent = item.content || '아직 작성한 내용이 없습니다.';
                article.append(title, text); content.append(article);
            }
            content.hidden = false; state.textContent = '비공개 · 로그인됨';
            status.textContent = '패스키로 본인 확인을 완료했습니다.';
            login.hidden = true; logout.hidden = false; registration.hidden = true;
            window.dispatchEvent(new CustomEvent('t08-auth-state', { detail: { authenticated: true } }));
            clearTimeout(expiryTimer);
            expiryTimer = setTimeout(() => lock('로그인 시간이 끝났습니다. 다시 로그인해 주세요.'), Math.max(0, Date.parse(data.expiresAt) - Date.now()));
        } catch {
            if (attempt === version) lock('연결을 확인하지 못했습니다. 페이지를 새로고침해 주세요.');
        }
    }
    login.addEventListener('click', async () => {
        if (busy) return;
        if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.get) { status.textContent = 'HTTPS 주소에서 패스키를 지원하는 브라우저를 이용해 주세요.'; return; }
        busy = true; login.disabled = true;
        let challengeId; let phase = 'options';
        try {
            status.textContent = '패스키 로그인을 준비하고 있습니다.';
            const data = await request('options', {}); challengeId = data.challengeId;
            const publicKey = typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
                ? PublicKeyCredential.parseRequestOptionsFromJSON(data.options)
                : { ...data.options, challenge: decode(data.options.challenge),
                    allowCredentials: (data.options.allowCredentials || []).map(item => ({ ...item, id: decode(item.id) })) };
            phase = 'device'; status.textContent = '등록한 패스키를 선택하고 기기에서 본인 확인을 진행해 주세요.';
            const credential = await navigator.credentials.get({ publicKey });
            if (!credential) throw new DOMException('Cancelled', 'NotAllowedError');
            const assertion = typeof credential.toJSON === 'function' ? credential.toJSON() : {
                id: credential.id, rawId: encode(credential.rawId), type: credential.type,
                response: { clientDataJSON: encode(credential.response.clientDataJSON), authenticatorData: encode(credential.response.authenticatorData),
                    signature: encode(credential.response.signature), userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null },
                clientExtensionResults: credential.getClientExtensionResults()
            };
            phase = 'verify'; await request('verify', { challengeId, credential: assertion });
            await refresh(); channel?.postMessage('login');
        } catch (error) {
            if (phase === 'device' && challengeId) {
                try { await request('cancel', { challengeId }); } catch { /* Expired questions remain unusable. */ }
            }
            lock(error.name === 'NotAllowedError' || error.name === 'AbortError' ? '로그인이 취소되었거나 시간이 지났습니다.' : error.message);
        } finally { busy = false; login.disabled = false; }
    });
    logout.addEventListener('click', async () => {
        if (busy) return;
        busy = true; lock('로그아웃하고 있습니다.'); logout.hidden = false; logout.disabled = true;
        try {
            await request('logout', {}); lock('로그아웃했습니다.');
            window.dispatchEvent(new CustomEvent('t08-auth-state', { detail: { authenticated: false } }));
            channel?.postMessage('logout');
        } catch {
            status.textContent = '화면은 잠겼지만 서버 로그아웃을 확인하지 못했습니다. 로그아웃을 다시 눌러 주세요.';
            logout.hidden = false;
        } finally { busy = false; logout.disabled = false; }
    });
    channel?.addEventListener('message', event => {
        if (event.data === 'logout') { lock('다른 탭에서 로그아웃했습니다.'); window.dispatchEvent(new CustomEvent('t08-auth-state', { detail: { authenticated: false } })); }
        else if (event.data === 'login') refresh();
    });
    window.addEventListener('pagehide', () => lock());
    window.addEventListener('pageshow', () => refresh());
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') refresh(); else lock(); });
    refresh();
})();

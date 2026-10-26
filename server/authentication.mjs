import { randomBytes, randomUUID } from 'node:crypto';
import { config, createDatabase, RequestError, json, bodyOf, sha } from './registration.mjs';
const SESSION = '__Host-t08_session';
const FLOW = '__Host-t08_login';
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const CREDENTIAL = /^[A-Za-z0-9_-]{1,2048}$/;
export function readToken(request, name = SESSION) {
    const values = (request.headers.get('cookie') || '').split(';').map(s => s.trim()).filter(s => s.startsWith(name + '='));
    if (values.length !== 1) return null;
    const value = values[0].slice(name.length + 1);
    return TOKEN.test(value) ? value : null;
}
function cookie(name, value, age) { return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${age}`; }
function cookies(response, values) { for (const value of values) response.headers.append('Set-Cookie', value); return response; }
const now = () => new Date().toISOString();
export async function readSession(request, db) {
    const token = readToken(request);
    if (!token) return null;
    const rows = await db.request(`t08_sessions?token_hash=eq.${sha(token)}&revoked_at=is.null&expires_at=gt.${encodeURIComponent(now())}&select=user_id,expires_at&limit=1`);
    return rows[0] || null;
}
async function webauthn() {
    try { return await import('@simplewebauthn/server'); }
    catch { throw new RequestError(503, 'PASSKEY_LIBRARY_UNAVAILABLE', '패스키 검증 라이브러리를 불러오지 못했습니다.'); }
}
function failure(error) {
    if (error instanceof RequestError) {
        if (error.status >= 500) console.error('t08_auth_error', error.code);
        return json({ error: error.code, message: error.message }, error.status);
    }
    console.error('t08_auth_service_unavailable');
    return json({ error: 'SERVICE_UNAVAILABLE', message: '로그인 서비스를 사용할 수 없습니다. 잠시 후 다시 시도해 주세요.' }, 503);
}
export function createAuthenticationHandler({ database = createDatabase, library = webauthn, configuration = config } = {}) {
    return async request => {
        try {
            const { origin, rpID } = configuration();
            const action = new URL(request.url).searchParams.get('action');
            if (request.method === 'GET' && action === 'session') {
                if (!readToken(request)) return json({ authenticated: false }, 401);
                const session = await readSession(request, database());
                return session ? json({ authenticated: true, expiresAt: session.expires_at }) : json({ authenticated: false }, 401);
            }
            if (request.method !== 'POST') return json({ error: 'METHOD_NOT_ALLOWED' }, 405, { Allow: 'GET, POST' });
            if (request.headers.get('origin') !== origin) return json({ error: 'ORIGIN_DENIED', message: '정식 사이트에서 로그인해 주세요.', expectedOrigin: origin, receivedOrigin: request.headers.get('origin') }, 403);
            if (!['options', 'verify', 'cancel', 'logout'].includes(action)) return json({ error: 'NOT_FOUND' }, 404);
            if (action === 'logout') {
                const token = readToken(request);
                if (token) await database().request(`t08_sessions?token_hash=eq.${sha(token)}&revoked_at=is.null`, 'PATCH', { revoked_at: now() });
                return cookies(json({ loggedOut: true }), [cookie(SESSION, '', 0), cookie(FLOW, '', 0), cookie('__Host-t08_enrollment', '', 0)]);
            }
            const data = await bodyOf(request);
            const db = database();
            if (action === 'options') {
                const { generateAuthenticationOptions } = await library();
                const options = await generateAuthenticationOptions({ rpID, userVerification: 'required', timeout: 120000 });
                const id = randomUUID(); const binding = randomBytes(32).toString('base64url');
                await db.request('t08_auth_challenges', 'POST', { id, challenge: options.challenge, binding_hash: sha(binding), expires_at: new Date(Date.now() + 300000).toISOString() });
                return cookies(json({ challengeId: id, options }), [cookie(FLOW, binding, 300)]);
            }
            const binding = readToken(request, FLOW);
            if (!binding || typeof data.challengeId !== 'string' || !ID.test(data.challengeId)) return json({ error: 'LOGIN_FLOW_REQUIRED', message: '로그인을 처음부터 다시 시작해 주세요.' }, 401);
            const filter = `id=eq.${data.challengeId}&binding_hash=eq.${sha(binding)}`;
            if (action === 'cancel') {
                await db.request(`t08_auth_challenges?${filter}&used_at=is.null`, 'DELETE');
                return cookies(json({ cancelled: true }), [cookie(FLOW, '', 0)]);
            }
            const questions = await db.request(`t08_auth_challenges?${filter}&select=*&limit=1`);
            const question = questions[0];
            if (!question || question.used_at || Date.parse(question.expires_at) <= Date.now()) return json({ error: 'CHALLENGE_USED_OR_EXPIRED', message: '이미 사용했거나 만료된 로그인 요청입니다.' }, 409);
            const response = data.credential;
            if (!response || typeof response.id !== 'string' || !CREDENTIAL.test(response.id)) return json({ error: 'INVALID_CREDENTIAL' }, 400);
            const keys = await db.request(`t08_passkeys?credential_id=eq.${response.id}&select=*&limit=1`);
            const key = keys[0];
            if (!key) return json({ error: 'AUTHENTICATION_FAILED', message: '등록한 패스키를 확인해 주세요.' }, 401);
            const users = await db.request(`t08_users?id=eq.${key.user_id}&select=webauthn_user_id&limit=1`);
            if (!users[0] || (response.response?.userHandle != null && response.response.userHandle !== users[0].webauthn_user_id)) return json({ error: 'AUTHENTICATION_FAILED', message: '등록한 패스키를 확인해 주세요.' }, 401);
            const { verifyAuthenticationResponse } = await library();
            let verification;
            try {
                verification = await verifyAuthenticationResponse({ response,
                    expectedChallenge: question.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
                    credential: { id: key.credential_id, publicKey: new Uint8Array(Buffer.from(key.public_key, 'base64url')), counter: Number(key.counter), transports: key.transports }
                });
            } catch { return json({ error: 'AUTHENTICATION_FAILED', message: '패스키 서명 확인에 실패했습니다.' }, 401); }
            if (!verification.verified || !verification.authenticationInfo) return json({ error: 'AUTHENTICATION_FAILED' }, 401);
            const sessionToken = randomBytes(32).toString('base64url'); const previous = readToken(request);
            await db.request('rpc/t08_finish_login', 'POST', { p_challenge_id: question.id, p_binding_hash: sha(binding), p_credential_id: key.credential_id,
                p_expected_counter: Number(key.counter), p_new_counter: verification.authenticationInfo.newCounter,
                p_session_hash: sha(sessionToken), p_previous_session_hash: previous ? sha(previous) : null });
            return cookies(json({ authenticated: true }), [cookie(SESSION, sessionToken, 3600), cookie(FLOW, '', 0)]);
        } catch (error) { return failure(error); }
    };
}
export function createPrivateInfoHandler({ database = createDatabase, configuration = config } = {}) {
    return async request => {
        try {
            if (!readToken(request)) return json({ error: 'AUTH_REQUIRED', message: '비공개 정보는 패스키 로그인 후 확인할 수 있습니다.' }, 401);
            const db = database(); const session = await readSession(request, db);
            if (!session) return json({ error: 'AUTH_REQUIRED', message: '로그인 시간이 끝났습니다. 다시 로그인해 주세요.' }, 401);
            if (!['GET', 'HEAD', 'POST'].includes(request.method)) return json({ error: 'METHOD_NOT_ALLOWED' }, 405, { Allow: 'GET, HEAD, POST' });
            if (request.method === 'POST') {
                if (request.headers.get('origin') !== configuration().origin) return json({ error: 'ORIGIN_DENIED' }, 403);
                // POST is a read-only query. A client-supplied owner is never authoritative.
                // Parse with the shared size/type limits, then discard all client selectors.
                await bodyOf(request);
            }
            const params = new URL(request.url).searchParams;
            for (const name of ['userId', 'user_id', 'owner_id']) {
                if (params.getAll(name).some(value => value !== session.user_id)) return json({ error: 'FORBIDDEN' }, 403);
            }
            const items = await db.request(`t08_private_items?user_id=eq.${session.user_id}&select=id,kind,title,content&order=created_at.asc,id.asc`);
            const result = json({ items, expiresAt: session.expires_at });
            return request.method === 'HEAD' ? new Response(null, { status: result.status, headers: result.headers }) : result;
        } catch (error) { return failure(error); }
    };
}

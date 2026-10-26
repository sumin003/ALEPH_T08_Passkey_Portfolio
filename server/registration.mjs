import { randomBytes, randomUUID, createHash } from "node:crypto";

const COOKIE = "__Host-t08_enrollment";
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const sha = value => createHash("sha256").update(value).digest("hex");
const safeHeaders = { "Cache-Control": "private, no-store, max-age=0", "Vary": "Cookie", "X-Content-Type-Options": "nosniff" };

class RequestError extends Error {
    constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

function json(body, status = 200, headers = {}) {
    return Response.json(body, { status, headers: { ...safeHeaders, ...headers } });
}

function readCookie(request) {
    const pairs = (request.headers.get("cookie") || "").split(";");
    const values = pairs.map(value => value.trim()).filter(value => value.startsWith(COOKIE + "="));
    if (values.length !== 1) return null;
    const token = values[0].slice(COOKIE.length + 1);
    return TOKEN.test(token) ? token : null;
}

function cookie(token, seconds) {
    return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${seconds}`;
}

export function config() {
    const value = (process.env.T08_ORIGIN || "https://alepht08passkeyportfolio.vercel.app").trim();
    let parsed;
    try { parsed = new URL(value); } catch {
        throw new RequestError(503, "ORIGIN_CONFIG_INVALID", "T08_ORIGIN에 올바른 HTTPS 사이트 주소를 설정해 주세요.");
    }
    if (parsed.protocol !== "https:" || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.username || parsed.password) {
        throw new RequestError(503, "ORIGIN_CONFIG_INVALID", "T08_ORIGIN에는 경로가 없는 HTTPS 사이트 주소를 설정해 주세요.");
    }
    return { origin: parsed.origin, rpID: parsed.hostname };
}

async function bodyOf(request) {
    if (!(request.headers.get("content-type") || "").startsWith("application/json")) {
        throw new RequestError(415, "JSON_REQUIRED", "요청 형식을 확인해 주세요.");
    }
    // Bound the body before buffering it; client Content-Length is not trusted.
    const reader = request.body?.getReader();
    if (!reader) throw new RequestError(400, "INVALID_REQUEST", "요청 내용이 없습니다.");
    let length = 0; const chunks = [];
    try {
        for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            length += value.length;
            if (length > 65536) { await reader.cancel(); throw new RequestError(413, "REQUEST_TOO_LARGE", "요청이 너무 큽니다."); }
            chunks.push(value);
        }
        const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error();
        return data;
    } catch (error) {
        if (error instanceof RequestError) throw error;
        throw new RequestError(400, "INVALID_REQUEST", "요청 내용을 확인해 주세요.");
    }
}

function label(value, limit) {
    if (typeof value !== "string" || !value.trim() || value.trim().length > limit || /[\x00-\x1f\x7f]/.test(value)) {
        throw new RequestError(400, "INVALID_LABEL", "패스키 이름과 저장 위치를 확인해 주세요.");
    }
    return value.trim();
}

// This client is server-only. No publishable key or secret is bundled into browser JS.
export function createDatabase() {
    const base = (process.env.SUPABASE_URL || "").trim().replace(/\/$/, "");
    const key = (process.env.SUPABASE_SECRET_KEY || "").trim();
    if (base !== "https://gywwtgecjkfmgnwkbmzl.supabase.co") {
        throw new RequestError(503, "DATABASE_URL_INVALID", "SUPABASE_URL을 지정한 Supabase 프로젝트 주소로 설정해 주세요.");
    }
    if (!key) throw new RequestError(503, "DATABASE_KEY_MISSING", "Vercel에 SUPABASE_SECRET_KEY를 설정한 뒤 재배포해 주세요.");
    async function query(path, method = "GET", body) {
        const headers = { apikey: key, "Content-Type": "application/json", Prefer: "return=representation" };
        if (!key.startsWith("sb_secret_")) headers.Authorization = `Bearer ${key}`;
        let response;
        try { response = await fetch(`${base}/rest/v1/${path}`, {
            method, headers, body: body === undefined ? undefined : JSON.stringify(body),
            cache: "no-store", signal: AbortSignal.timeout(8000)
        }); } catch {
            throw new RequestError(503, "DATABASE_UNREACHABLE", "서버에서 DB에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.");
        }
        if (!response.ok) {
            // Never expose upstream response bodies, credentials, request data or stack traces.
            if (response.status === 409) throw new RequestError(409, "ALREADY_REGISTERED", "이미 등록된 패스키입니다.");
            if (path.startsWith("rpc/") && response.status === 400) throw new RequestError(409, "CHALLENGE_USED", "이미 사용했거나 만료된 등록 요청입니다.");
            if (response.status === 401 || response.status === 403) {
                throw new RequestError(503, "DATABASE_ACCESS_DENIED", "Supabase 서버 전용 키와 T08 테이블 권한을 확인해 주세요.");
            }
            if (response.status === 404) throw new RequestError(503, "DATABASE_SCHEMA_MISSING", "Supabase의 T08 테이블과 등록 함수를 확인해 주세요.");
            throw new RequestError(503, "DATABASE_REQUEST_FAILED", "DB 요청을 처리하지 못했습니다. 서버 기록을 확인해 주세요.");
        }
        return response.status === 204 ? null : response.json();
    }
    return {
        findEnrollment: hash => query(`t08_users?enrollment_token_hash=eq.${hash}&enrollment_expires_at=gt.${encodeURIComponent(new Date().toISOString())}&select=id&limit=1`).then(rows => rows[0] || null),
        list: user => query(`t08_passkeys?user_id=eq.${user}&select=name,created_at,storage_label,device_type,backed_up&order=created_at.asc`),
        create: row => query("t08_challenges", "POST", row),
        findChallenge: (id, hash) => query(`t08_challenges?id=eq.${id}&binding_hash=eq.${hash}&select=*&limit=1`).then(rows => rows[0] || null),
        cancel: (id, hash) => query(`t08_challenges?id=eq.${id}&binding_hash=eq.${hash}&used_at=is.null`, "DELETE"),
        finish: data => query("rpc/t08_finish_registration", "POST", data)
    };
}

async function webauthn() {
    try { return await import("@simplewebauthn/server"); } catch {
        throw new RequestError(503, "PASSKEY_LIBRARY_UNAVAILABLE", "패스키 검증 라이브러리를 불러오지 못했습니다. 배포 기록을 확인해 주세요.");
    }
}

// Dependency injection is only available to server-side tests, never HTTP request input.
export function createRegistrationHandler({ database = createDatabase, library = webauthn, configuration = config } = {}) {
    return async function handle(request) {
        try {
            const { origin, rpID } = configuration();
            if (request.method !== "GET" && request.headers.get("origin") !== origin) {
                throw new RequestError(403, "ORIGIN_DENIED", "이 사이트에서 등록을 진행해 주세요.");
            }
            const url = new URL(request.url);
            const action = url.searchParams.get("action");
            const token = readCookie(request);
            if (request.method === "GET" && action === "list") {
                if (!token) return json({ error: "REGISTRATION_SESSION_REQUIRED" }, 401);
                const db = database();
                const user = await db.findEnrollment(sha(token));
                if (!user) return json({ error: "REGISTRATION_SESSION_REQUIRED" }, 401);
                return json({ passkeys: await db.list(user.id) });
            }
            if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED" }, 405, { Allow: "GET, POST" });
            if (!["options", "verify", "cancel"].includes(action)) return json({ error: "NOT_FOUND" }, 404);
            const data = await bodyOf(request);
            const db = database();
            if (action === "options") {
                const name = label(data.name, 60);
                const storage = label(data.storage, 100);
                if (token && await db.findEnrollment(sha(token))) {
                    throw new RequestError(409, "LOGIN_REQUIRED_TO_ADD", "첫 패스키가 등록되어 있습니다. 추가 등록은 로그인 기능 연결 후 이용할 수 있습니다.");
                }
                const userId = randomUUID();
                const userBytes = Buffer.from(userId.replaceAll("-", ""), "hex");
                const binding = randomBytes(32).toString("base64url");
                const { generateRegistrationOptions } = await library();
                const options = await generateRegistrationOptions({
                    rpName: "우수민 Portfolio", rpID,
                    userID: new Uint8Array(userBytes),
                    userName: `portfolio-${userId.slice(-8)}`,
                    attestationType: "none", timeout: 120000,
                    authenticatorSelection: { residentKey: "required", userVerification: "required" },
                    supportedAlgorithmIDs: [-7, -257]
                });
                const id = randomUUID();
                await db.create({ id, kind: "registration", challenge: options.challenge,
                    binding_hash: sha(binding), candidate_user_id: userId,
                    webauthn_user_id: options.user.id, passkey_name: name, storage_label: storage,
                    expires_at: new Date(Date.now() + 5 * 60000).toISOString() });
                return json({ challengeId: id, options }, 200, { "Set-Cookie": cookie(binding, 300) });
            }
            if (!token || typeof data.challengeId !== "string" || !UUID.test(data.challengeId)) {
                throw new RequestError(401, "REGISTRATION_SESSION_REQUIRED", "등록을 처음부터 다시 시작해 주세요.");
            }
            if (action === "cancel") {
                await db.cancel(data.challengeId, sha(token));
                return json({ cancelled: true }, 200, { "Set-Cookie": cookie("", 0) });
            }
            const challenge = await db.findChallenge(data.challengeId, sha(token));
            if (!challenge || challenge.kind !== "registration" || challenge.used_at || Date.parse(challenge.expires_at) <= Date.now()) {
                throw new RequestError(409, "CHALLENGE_USED_OR_EXPIRED", "이미 사용했거나 만료된 등록 요청입니다.");
            }
            const { verifyRegistrationResponse } = await library();
            let verification;
            try {
                verification = await verifyRegistrationResponse({ response: data.credential,
                    expectedChallenge: challenge.challenge, expectedOrigin: origin,
                    expectedRPID: rpID, requireUserVerification: true });
            } catch { throw new RequestError(400, "VERIFICATION_FAILED", "기기의 등록 응답을 확인하지 못했습니다. 다시 등록해 주세요."); }
            if (!verification.verified || !verification.registrationInfo) {
                throw new RequestError(400, "VERIFICATION_FAILED", "등록 응답 검증에 실패했습니다.");
            }
            const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
            await db.finish({ p_challenge_id: challenge.id, p_binding_hash: sha(token),
                p_credential_id: credential.id, p_public_key: Buffer.from(credential.publicKey).toString("base64url"),
                p_counter: credential.counter, p_transports: credential.transports || [],
                p_device_type: credentialDeviceType, p_backed_up: credentialBackedUp });
            return json({ registered: true, passkey: { name: challenge.passkey_name,
                storage_label: challenge.storage_label }, privateAccessGranted: false },
                200, { "Set-Cookie": cookie(token, 900) });
        } catch (error) {
            if (error instanceof RequestError) {
                if (error.status >= 500) console.error("t08_registration_error", error.code);
                return json({ error: error.code, message: error.message }, error.status);
            }
            console.error("t08_registration_service_unavailable");
            return json({ error: "SERVICE_UNAVAILABLE", message: "등록 서비스를 사용할 수 없습니다. 설정과 연결을 확인해 주세요." }, 503);
        }
    };
}

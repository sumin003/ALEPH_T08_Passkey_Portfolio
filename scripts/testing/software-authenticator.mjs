// Test-only software authenticator. Real ES256 signatures, NO device/PIN verification.
// Never imported by api/, server/ or browser assets. Private keys remain in process memory.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
export const digest = value => createHash('sha256').update(value).digest();
function head(major, length) {
    if (length < 24) return Buffer.from([(major << 5) | length]);
    if (length < 256) return Buffer.from([(major << 5) | 24, length]);
    if (length < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(length, 1); return b; }
    throw new Error('Test CBOR length exceeded');
}
export function cbor(value) {
    if (Number.isSafeInteger(value)) return value >= 0 ? head(0, value) : head(1, -value - 1);
    if (typeof value === 'string') { const b = Buffer.from(value); return Buffer.concat([head(3, b.length), b]); }
    if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
    if (value instanceof Map) return Buffer.concat([head(5, value.size), ...Array.from(value, ([k, v]) => [cbor(k), cbor(v)]).flat()]);
    throw new Error('Unsupported test CBOR type');
}
function counter(value) { const b = Buffer.alloc(4); b.writeUInt32BE(value); return b; }
export function accountId(userHandle) {
    const b = Buffer.from(userHandle, 'base64url');
    if (b.length !== 16) throw new Error('First registration user handle format changed; stop without seeding.');
    const h = b.toString('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
export function makeSoftwareAuthenticator() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicKey.export({ format: 'jwk' });
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const rawId = randomBytes(32), id = rawId.toString('base64url');
    let userHandle, count = 0;
    return {
        id, publicKey, publicKeyCose: cose.toString('base64url'),
        registration(options, origin) {
            if (new URL(origin).hostname !== options.rp.id) throw new Error('Unexpected RP ID');
            userHandle = options.user.id;
            const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
            const len = Buffer.alloc(2); len.writeUInt16BE(rawId.length);
            const authData = Buffer.concat([digest(options.rp.id), Buffer.from([0x45]), counter(0), Buffer.alloc(16), len, rawId, cose]);
            const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
            return { id, rawId: id, type: 'public-key', clientExtensionResults: {},
                response: { clientDataJSON: clientDataJSON.toString('base64url'), attestationObject: attestationObject.toString('base64url'), transports: [] } };
        },
        assertion(options, origin) {
            if (!userHandle) throw new Error('Register test key before signing');
            if (new URL(origin).hostname !== options.rpId) throw new Error('Unexpected RP ID');
            const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
            const authenticatorData = Buffer.concat([digest(options.rpId), Buffer.from([0x05]), counter(++count)]);
            const signature = sign('sha256', Buffer.concat([authenticatorData, digest(clientDataJSON)]), privateKey);
            return { id, rawId: id, type: 'public-key', clientExtensionResults: {}, response: {
                clientDataJSON: clientDataJSON.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'), signature: signature.toString('base64url'), userHandle } };
        }
    };
}

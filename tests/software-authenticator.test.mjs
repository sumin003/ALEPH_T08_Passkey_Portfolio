import test from 'node:test';
import assert from 'node:assert/strict';
import { verify, generateKeyPairSync } from 'node:crypto';
import { makeSoftwareAuthenticator, digest, accountId } from '../scripts/testing/software-authenticator.mjs';
const origin = 'https://alepht08passkeyportfolio.vercel.app';
const rpID = new URL(origin).hostname;
const user = Buffer.from('11111111111141118111111111111111', 'hex').toString('base64url');
const options = { rp: { id: rpID }, user: { id: user }, challenge: 'test-registration-challenge' };

test('software test authenticator signs with an actual key and signatures fail under another key', () => {
    const key = makeSoftwareAuthenticator(); key.registration(options, origin);
    const response = key.assertion({ rpId: rpID, challenge: 'test-login-challenge' }, origin).response;
    const data = Buffer.concat([Buffer.from(response.authenticatorData, 'base64url'), digest(Buffer.from(response.clientDataJSON, 'base64url'))]);
    const signature = Buffer.from(response.signature, 'base64url');
    assert.ok(verify('sha256', data, key.publicKey, signature));
    assert.ok(!verify('sha256', data, generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey, signature));
    const modified = Buffer.from(data); modified[0] ^= 1;
    assert.ok(!verify('sha256', modified, key.publicKey, signature));
    assert.equal(accountId(user), '11111111-1111-4111-8111-111111111111');
    assert.ok(!JSON.stringify(key).includes('PRIVATE KEY'));
});

let library;
try { library = await import('@simplewebauthn/server'); } catch { /* Explicit skip if dependencies are unavailable. */ }
test('real SimpleWebAuthn accepts generated registration/login and rejects a different-key signature', { skip: !library && 'Install project dependencies to run actual SimpleWebAuthn verification' }, async () => {
    const key = makeSoftwareAuthenticator();
    const response = key.registration(options, origin);
    const registration = await library.verifyRegistrationResponse({ response, expectedChallenge: options.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true });
    assert.equal(registration.verified, true);
    assert.equal(Buffer.from(registration.registrationInfo.credential.publicKey).toString('base64url'), key.publicKeyCose);
    const loginOptions = { rpId: rpID, challenge: 'fresh-login-challenge' };
    const assertion = key.assertion(loginOptions, origin);
    const verifyOptions = { response: assertion, expectedChallenge: loginOptions.challenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true, credential: registration.registrationInfo.credential };
    const authentication = await library.verifyAuthenticationResponse(verifyOptions);
    assert.equal(authentication.verified, true);
    const other = makeSoftwareAuthenticator(); other.registration(options, origin);
    const invalid = { ...assertion, response: { ...assertion.response, signature: other.assertion(loginOptions, origin).response.signature } };
    let rejected = false;
    try { rejected = !(await library.verifyAuthenticationResponse({ ...verifyOptions, response: invalid })).verified; } catch { rejected = true; }
    assert.ok(rejected);
});

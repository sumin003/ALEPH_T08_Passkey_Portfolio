import { createAuthenticationHandler } from '../server/authentication.mjs';
export default { fetch: createAuthenticationHandler() };

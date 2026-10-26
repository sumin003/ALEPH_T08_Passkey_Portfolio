import { createPrivateInfoHandler } from '../server/authentication.mjs';
const handle = createPrivateInfoHandler();
export default {
    async fetch(request) {
        const response = await handle(request);
        return request.method === 'HEAD' ? new Response(null, { status: response.status, headers: response.headers }) : response;
    }
};

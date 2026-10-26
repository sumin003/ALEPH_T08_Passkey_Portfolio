// Card 1: registration and passkey verification are not implemented yet.
// Every request is denied until Card 3 supplies a verified server-side session.
// Do not accept cookie existence, user IDs, query flags or localStorage as proof.
export default {
    fetch(request) {
        const headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "private, no-store, max-age=0",
            "Vary": "Cookie",
            "X-Content-Type-Options": "nosniff"
        };

        // An HTTP HEAD response must not contain a response body.
        const body = request.method === "HEAD" ? null : JSON.stringify({
            error: "AUTH_REQUIRED",
            message: "비공개 정보는 패스키 로그인 후 확인할 수 있습니다."
        });

        return new Response(body, { status: 401, headers });
    }
};

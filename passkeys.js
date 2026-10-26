(() => {
    // Passkeys are bound to one RP domain. Keep Vercel preview visits on that domain.
    const registrationOrigin = "https://alepht08passkeyportfolio.vercel.app";
    if (window.location.hostname.endsWith(".vercel.app") && window.location.origin !== registrationOrigin) {
        window.location.replace(registrationOrigin + "/#private-info");
        return;
    }
    const form = document.getElementById("passkey-form");
    if (!form) return;
    const button = document.getElementById("passkey-register");
    const status = document.getElementById("passkey-status");
    const panel = document.getElementById("passkey-list-panel");
    const list = document.getElementById("passkey-list");
    let busy = false;

    function decode(value) {
        const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
        return Uint8Array.from(atob(base64 + "=".repeat((4 - base64.length % 4) % 4)), char => char.charCodeAt(0));
    }
    function encode(value) {
        return btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    }
    async function api(action, body) {
        const response = await fetch(`/api/passkeys?action=${action}`, {
            method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
            headers: body === undefined ? {} : { "Content-Type": "application/json" },
            body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000)
        });
        let data;
        try { data = await response.json(); } catch { throw new Error("서버 응답을 확인하지 못했습니다."); }
        if (!response.ok) {
            const error = new Error(data.message || "등록 정보를 확인하지 못했습니다.");
            error.status = response.status;
            throw error;
        }
        return data;
    }
    async function refreshList() {
        try {
            const data = await api("list");
            list.replaceChildren();
            for (const item of data.passkeys || []) {
                const row = document.createElement("li");
                const name = document.createElement("strong");
                const meta = document.createElement("small");
                name.textContent = item.name;
                const date = new Date(item.created_at).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" });
                meta.textContent = `${item.storage_label} · 등록: ${date} (한국 시간)`;
                row.append(name, meta); list.append(row);
            }
            panel.hidden = !list.children.length;
            if (list.children.length) button.disabled = true;
            return !!list.children.length;
        } catch (error) {
            panel.hidden = true;
            if (error.status !== 401) status.textContent = "패스키 목록을 불러오지 못했습니다.";
            return false;
        }
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();
        if (busy) return;
        if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.create) {
            status.textContent = "HTTPS 주소에서 패스키를 지원하는 브라우저와 기기로 이용해 주세요.";
            return;
        }
        busy = true; button.disabled = true;
        let challengeId; let phase = "options"; let registered = false;
        try {
            status.textContent = "패스키 등록을 준비하고 있습니다.";
            const data = await api("options", {
                name: document.getElementById("passkey-name").value,
                storage: document.getElementById("passkey-storage").value
            });
            challengeId = data.challengeId;
            const publicKey = typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function"
                ? PublicKeyCredential.parseCreationOptionsFromJSON(data.options)
                : { ...data.options, challenge: decode(data.options.challenge),
                    user: { ...data.options.user, id: decode(data.options.user.id) },
                    excludeCredentials: (data.options.excludeCredentials || []).map(item => ({ ...item, id: decode(item.id) })) };
            phase = "device";
            status.textContent = "기기에 표시된 창에서 패스키 등록을 진행해 주세요.";
            const credential = await navigator.credentials.create({ publicKey });
            if (!credential) throw new DOMException("Cancelled", "NotAllowedError");
            const result = typeof credential.toJSON === "function" ? credential.toJSON() : {
                id: credential.id, rawId: encode(credential.rawId), type: credential.type,
                authenticatorAttachment: credential.authenticatorAttachment,
                response: { clientDataJSON: encode(credential.response.clientDataJSON),
                    attestationObject: encode(credential.response.attestationObject),
                    transports: credential.response.getTransports?.() || [] },
                clientExtensionResults: credential.getClientExtensionResults()
            };
            phase = "verify";
            status.textContent = "기기의 응답을 확인하고 있습니다.";
            await api("verify", { challengeId, credential: result });
            registered = true;
            status.textContent = "패스키가 등록되었습니다.";
            if (!await refreshList()) status.textContent = "패스키는 등록됐지만 목록을 불러오지 못했습니다. 페이지를 새로고침해 주세요.";
        } catch (error) {
            if (phase === "device" && challengeId) {
                try {
                    await api("cancel", { challengeId });
                    status.textContent = error.name === "NotAllowedError" || error.name === "AbortError"
                        ? "등록이 취소되었거나 시간이 지났습니다. 패스키는 저장되지 않았습니다."
                        : "기기에서 등록을 완료하지 못했습니다. 패스키는 저장되지 않았습니다.";
                } catch {
                    status.textContent = "등록을 완료하지 못했습니다. 취소 요청의 서버 반영 여부는 연결 후 확인이 필요합니다.";
                }
            } else if (phase === "verify" && await refreshList()) {
                registered = true;
                status.textContent = "서버에 등록된 패스키를 확인했습니다.";
            } else {
                status.textContent = error.message || "등록을 완료하지 못했습니다. 다시 시도해 주세요.";
            }
        } finally {
            busy = false; button.disabled = registered;
        }
    });
    window.addEventListener("t08-auth-state", event => {
        if (event.detail.authenticated) refreshList();
        else { list.replaceChildren(); panel.hidden = true; button.disabled = false; }
    });
    refreshList();
})();
